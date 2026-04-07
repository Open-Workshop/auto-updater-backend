from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from kube.mirror_instance import GROUP, PLURAL, VERSION


@dataclass
class KubeClients:
    api_client: client.ApiClient
    core: client.CoreV1Api
    apps: client.AppsV1Api
    custom: client.CustomObjectsApi


_CLIENTS: KubeClients | None = None


def get_kube_clients() -> KubeClients:
    global _CLIENTS
    if _CLIENTS is not None:
        return _CLIENTS
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    api_client = client.ApiClient()
    _CLIENTS = KubeClients(
        api_client=api_client,
        core=client.CoreV1Api(api_client),
        apps=client.AppsV1Api(api_client),
        custom=client.CustomObjectsApi(api_client),
    )
    return _CLIENTS


def get_instance(namespace: str, name: str) -> dict[str, Any]:
    return get_kube_clients().custom.get_namespaced_custom_object(
        GROUP,
        VERSION,
        namespace,
        PLURAL,
        name,
    )


def list_instances(namespace: str) -> list[dict[str, Any]]:
    response = get_kube_clients().custom.list_namespaced_custom_object(
        GROUP,
        VERSION,
        namespace,
        PLURAL,
    )
    return list(response.get("items") or [])


def patch_instance(namespace: str, name: str, patch: dict[str, Any]) -> dict[str, Any]:
    return get_kube_clients().custom.patch_namespaced_custom_object(
        GROUP,
        VERSION,
        namespace,
        PLURAL,
        name,
        patch,
    )


def replace_or_create_instance(namespace: str, name: str, body: dict[str, Any]) -> dict[str, Any]:
    api = get_kube_clients().custom
    try:
        current = api.get_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL, name)
    except ApiException as exc:
        if exc.status != 404:
            raise
        return api.create_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL, body)
    body["metadata"] = dict(body.get("metadata") or {})
    body["metadata"]["resourceVersion"] = current.get("metadata", {}).get("resourceVersion")
    return api.replace_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL, name, body)


def delete_instance(namespace: str, name: str) -> None:
    try:
        get_kube_clients().custom.delete_namespaced_custom_object(
            GROUP,
            VERSION,
            namespace,
            PLURAL,
            name,
        )
    except ApiException as exc:
        if exc.status != 404:
            raise


def merge_instance_status(namespace: str, name: str, patch_fields: dict[str, Any]) -> dict[str, Any]:
    api = get_kube_clients().custom
    current = api.get_namespaced_custom_object(GROUP, VERSION, namespace, PLURAL, name)
    status = dict(current.get("status") or {})
    status.update(patch_fields)
    return api.patch_namespaced_custom_object_status(
        GROUP,
        VERSION,
        namespace,
        PLURAL,
        name,
        {"status": status},
    )


def _preserve_service_fields(current: Any, body: dict[str, Any]) -> None:
    spec = body.setdefault("spec", {})
    if getattr(current.spec, "cluster_ip", None):
        spec["clusterIP"] = current.spec.cluster_ip
    if getattr(current.spec, "cluster_ips", None):
        spec["clusterIPs"] = list(current.spec.cluster_ips)
    if getattr(current.spec, "ip_families", None):
        spec["ipFamilies"] = list(current.spec.ip_families)
    if getattr(current.spec, "ip_family_policy", None):
        spec["ipFamilyPolicy"] = current.spec.ip_family_policy
    if getattr(current.spec, "health_check_node_port", None):
        spec["healthCheckNodePort"] = current.spec.health_check_node_port


def upsert_secret(namespace: str, body: dict[str, Any]) -> dict[str, Any]:
    api = get_kube_clients().core
    name = body["metadata"]["name"]
    try:
        current = api.read_namespaced_secret(name, namespace)
    except ApiException as exc:
        if exc.status != 404:
            raise
        return api.create_namespaced_secret(namespace, body)
    body["metadata"]["resourceVersion"] = current.metadata.resource_version
    return api.replace_namespaced_secret(name, namespace, body)


def upsert_service(namespace: str, body: dict[str, Any]) -> dict[str, Any]:
    api = get_kube_clients().core
    name = body["metadata"]["name"]
    try:
        current = api.read_namespaced_service(name, namespace)
    except ApiException as exc:
        if exc.status != 404:
            raise
        return api.create_namespaced_service(namespace, body)
    body["metadata"]["resourceVersion"] = current.metadata.resource_version
    _preserve_service_fields(current, body)
    return api.replace_namespaced_service(name, namespace, body)


def upsert_statefulset(namespace: str, body: dict[str, Any]) -> dict[str, Any]:
    api = get_kube_clients().apps
    name = body["metadata"]["name"]
    try:
        current = api.read_namespaced_stateful_set(name, namespace)
    except ApiException as exc:
        if exc.status != 404:
            raise
        return api.create_namespaced_stateful_set(namespace, body)
    body["metadata"]["resourceVersion"] = current.metadata.resource_version
    return api.replace_namespaced_stateful_set(name, namespace, body)


def read_secret_value(namespace: str, name: str, key: str) -> str:
    import base64

    secret = get_kube_clients().core.read_namespaced_secret(name, namespace)
    data = dict(secret.data or {})
    if key not in data:
        raise KeyError(f"secret {name} does not contain key {key}")
    return base64.b64decode(data[key]).decode("utf-8")


def delete_secret(namespace: str, name: str) -> None:
    try:
        get_kube_clients().core.delete_namespaced_secret(name, namespace)
    except ApiException as exc:
        if exc.status != 404:
            raise


def read_pod_log(
    namespace: str,
    name: str,
    *,
    container: str | None = None,
    tail_lines: int = 200,
) -> str:
    return get_kube_clients().core.read_namespaced_pod_log(
        name=name,
        namespace=namespace,
        container=container,
        tail_lines=tail_lines,
    )


def read_pod_log_merged(
    namespace: str,
    name: str,
    containers: list[str],
    *,
    tail_lines: int = 200,
) -> str:
    """Read and merge logs from multiple containers in a pod.
    
    Logs are merged and sorted by timestamp.
    """
    from kubernetes.client.rest import ApiException
    
    all_lines: list[tuple[str, str]] = []  # (timestamp, line)
    
    for container in containers:
        try:
            log_text = get_kube_clients().core.read_namespaced_pod_log(
                name=name,
                namespace=namespace,
                container=container,
                tail_lines=tail_lines,
            )
            # Parse each line to extract timestamp
            for line in log_text.splitlines():
                # Try to extract timestamp from common log formats
                # Format: "2026-04-07 16:34:50,123 message"
                import re
                timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)', line)
                if timestamp_match:
                    timestamp = timestamp_match.group(1)
                    all_lines.append((timestamp, line))
                else:
                    # No timestamp found, use current time as fallback
                    all_lines.append(("", line))
        except ApiException as exc:
            if exc.status != 404:
                raise
    
    # Sort by timestamp
    all_lines.sort(key=lambda x: x[0])
    
    # Return merged logs
    return "\n".join(line for _, line in all_lines)
