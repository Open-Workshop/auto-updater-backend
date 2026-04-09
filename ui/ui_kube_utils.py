"""Kubernetes utilities for UI service."""
from __future__ import annotations

import ast
import json
import logging
from typing import Any

from kubernetes.client.rest import ApiException

from kube.kube_client import get_kube_clients
from ui.ui_formatting import _parse_bytes, _parse_cpu_millicores, _int_value


def _select_best_pod(pods: list[Any]) -> Any | None:
    """Select the best pod from a list (not deleting, most recent)."""
    if not pods:
        return None
    ranked = sorted(
        pods,
        key=lambda item: (
            item.metadata.deletion_timestamp is None,
            item.metadata.creation_timestamp.isoformat() if item.metadata.creation_timestamp else "",
        ),
        reverse=True,
    )
    return ranked[0]


def _pod_snapshot(pod: Any | None) -> dict[str, Any]:
    """Create a snapshot of pod state."""
    if pod is None:
        return {
            "podName": "",
            "phase": "Missing",
            "ready": False,
            "deleting": False,
            "images": {},
            "containerReady": {},
            "nodeName": "",
        }
    container_statuses = list(getattr(pod.status, "container_statuses", None) or [])
    container_ready = {status.name: bool(status.ready) for status in container_statuses}
    images = {container.name: container.image for container in list(getattr(pod.spec, "containers", None) or [])}
    conditions = {condition.type: condition.status for condition in list(getattr(pod.status, "conditions", None) or [])}
    # Try both node_name (snake_case) and nodeName (camelCase) for compatibility
    node_name = getattr(pod.spec, "node_name", None) or getattr(pod.spec, "nodeName", None) or ""
    logging.debug("_pod_snapshot: pod=%s, nodeName=%r", pod.metadata.name, node_name)
    return {
        "podName": str(pod.metadata.name or ""),
        "phase": str(getattr(pod.status, "phase", "") or "Unknown"),
        "ready": conditions.get("Ready") == "True",
        "deleting": getattr(pod.metadata, "deletion_timestamp", None) is not None,
        "images": images,
        "containerReady": container_ready,
        "nodeName": str(node_name),
    }


def _read_node_stats_summary(node_name: str) -> dict[str, Any]:
    """Read node stats summary via kubelet proxy."""
    proxy = getattr(get_kube_clients().core, "connect_get_node_proxy_with_path", None)
    if proxy is None:
        return {}
    raw = proxy(node_name, "stats/summary")
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            parsed = ast.literal_eval(raw)
            if isinstance(parsed, dict):
                return parsed
            return {}
    return dict(raw or {})


def _get_node_cpu_capacity(node_name: str) -> int | None:
    """Get CPU capacity of a node in millicores."""
    try:
        node = get_kube_clients().core.read_node(node_name)
        if node.status is None or node.status.capacity is None:
            logging.warning("Node %s has no status or capacity", node_name)
            return None
        cpu_raw = node.status.capacity.get("cpu")
        logging.debug("Node %s CPU capacity raw: %r (type: %s)", node_name, cpu_raw, type(cpu_raw))
        cpu_value = _parse_cpu_millicores(cpu_raw)
        if cpu_value is None:
            logging.warning("Could not parse CPU capacity for node %s, raw value: %r", node_name, cpu_raw)
        else:
            logging.debug("Node %s CPU capacity parsed: %d millicores", node_name, cpu_value)
        return cpu_value
    except Exception as exc:
        logging.warning("Failed to get node CPU capacity for %s: %s", node_name, exc)
        return None


def _get_node_memory_capacity(node_name: str) -> int | None:
    """Get memory capacity of a node in bytes."""
    try:
        node = get_kube_clients().core.read_node(node_name)
        if node.status is None or node.status.capacity is None:
            logging.warning("Node %s has no status or capacity", node_name)
            return None
        memory_raw = node.status.capacity.get("memory")
        logging.debug("Node %s memory capacity raw: %r (type: %s)", node_name, memory_raw, type(memory_raw))
        memory_value = _parse_bytes(memory_raw)
        if memory_value is None:
            logging.warning("Could not parse memory capacity for node %s, raw value: %r", node_name, memory_raw)
        else:
            logging.debug("Node %s memory capacity parsed: %d bytes", node_name, memory_value)
        return memory_value
    except Exception as exc:
        logging.warning("Failed to get node memory capacity for %s: %s", node_name, exc)
        return None


def _get_cluster_cpu_capacity() -> int | None:
    """Get total CPU capacity of the cluster in millicores."""
    try:
        nodes = get_kube_clients().core.list_node().items or []
        total_capacity = 0
        for node in nodes:
            capacity = dict(node.status.capacity or {}) if node.status else {}
            cpu_value = _parse_cpu_millicores(capacity.get("cpu"))
            if cpu_value is not None:
                total_capacity += cpu_value
        logging.debug("_get_cluster_cpu_capacity: total_capacity=%d", total_capacity)
        return total_capacity if total_capacity > 0 else None
    except Exception as e:
        logging.error("_get_cluster_cpu_capacity: exception=%s", e)
        return None


def _get_cluster_memory_capacity() -> int | None:
    """Get total memory capacity of the cluster in bytes."""
    try:
        nodes = get_kube_clients().core.list_node().items or []
        total_capacity = 0
        for node in nodes:
            capacity = dict(node.status.capacity or {}) if node.status else {}
            memory_value = _parse_bytes(capacity.get("memory"))
            if memory_value is not None:
                total_capacity += memory_value
        logging.debug("_get_cluster_memory_capacity: total_capacity=%d", total_capacity)
        return total_capacity if total_capacity > 0 else None
    except Exception as e:
        logging.error("_get_cluster_memory_capacity: exception=%s", e)
        return None


def _get_cluster_disk_stats() -> dict[str, int | None]:
    """Get total filesystem capacity and used bytes across cluster nodes."""
    total_capacity = 0
    total_used = 0
    capacity_seen = False
    used_seen = False
    try:
        nodes = get_kube_clients().core.list_node().items or []
    except Exception as exc:
        logging.error("_get_cluster_disk_stats: failed to list nodes: %s", exc)
        return {"capacityBytes": None, "usedBytes": None}
    for node in nodes:
        node_name = str(getattr(getattr(node, "metadata", None), "name", "") or "")
        if not node_name:
            continue
        try:
            summary = _read_node_stats_summary(node_name)
        except ApiException as exc:
            logging.warning(
                "_get_cluster_disk_stats: ApiException for node %s status=%s body=%r",
                node_name,
                exc.status,
                exc.body,
            )
            if exc.status in {403, 404, 503}:
                continue
            raise
        except json.JSONDecodeError:
            logging.warning(
                "_get_cluster_disk_stats: failed to decode stats summary for node %s",
                node_name,
            )
            continue
        node_stats = dict(summary.get("node") or {})
        fs_stats = dict(node_stats.get("fs") or {})
        capacity_value = _int_value(fs_stats.get("capacityBytes"))
        used_value = _int_value(fs_stats.get("usedBytes"))
        if capacity_value is not None:
            total_capacity += capacity_value
            capacity_seen = True
        if used_value is not None:
            total_used += used_value
            used_seen = True
    return {
        "capacityBytes": total_capacity if capacity_seen else None,
        "usedBytes": total_used if used_seen else None,
    }


def _pod_usage_metrics(namespace: str, pod_names: set[str]) -> dict[str, dict[str, int | None]]:
    """Get CPU, memory, and network usage metrics for pods."""
    logging.debug("_pod_usage_metrics: namespace=%s, pod_names=%r", namespace, pod_names)
    if not pod_names:
        return {}
    try:
        response = get_kube_clients().custom.list_namespaced_custom_object(
            "metrics.k8s.io",
            "v1beta1",
            namespace,
            "pods",
        )
        logging.debug("_pod_usage_metrics: response items count=%d", len(response.get("items", [])))
    except ApiException as exc:
        logging.warning("_pod_usage_metrics: ApiException status=%d, body=%r", exc.status, exc.body)
        if exc.status in {403, 404, 503}:
            return {}
        raise
    metrics: dict[str, dict[str, int | None]] = {}
    for item in list(response.get("items") or []):
        metadata = dict(item.get("metadata") or {})
        pod_name = str(metadata.get("name") or "")
        if pod_name not in pod_names:
            continue
        total_cpu = 0
        total_memory = 0
        total_rx_bytes = 0
        total_tx_bytes = 0
        cpu_seen = False
        memory_seen = False
        network_seen = False
        for container in list(item.get("containers") or []):
            usage = dict(container.get("usage") or {})
            cpu_value = _parse_cpu_millicores(usage.get("cpu"))
            memory_value = _parse_bytes(usage.get("memory"))
            rx_value = _parse_bytes(usage.get("rx_bytes"))
            tx_value = _parse_bytes(usage.get("tx_bytes"))
            if cpu_value is not None:
                total_cpu += cpu_value
                cpu_seen = True
            if memory_value is not None:
                total_memory += memory_value
                memory_seen = True
            if rx_value is not None:
                total_rx_bytes += rx_value
                network_seen = True
            if tx_value is not None:
                total_tx_bytes += tx_value
                network_seen = True
        metrics[pod_name] = {
            "cpuMilliCores": total_cpu if cpu_seen else None,
            "memoryBytes": total_memory if memory_seen else None,
            "rxBytes": total_rx_bytes if network_seen else None,
            "txBytes": total_tx_bytes if network_seen else None,
        }
    return metrics


def _pod_network_metrics(namespace: str, pod_name: str) -> dict[str, int | None]:
    """Get network metrics for a specific pod from kubelet stats/summary."""
    logging.debug("_pod_network_metrics: namespace=%s, pod_name=%s", namespace, pod_name)
    if not pod_name:
        return {}
    try:
        # Get the pod to find its node
        pod = get_kube_clients().core.read_namespaced_pod(pod_name, namespace)
        node_name = pod.spec.node_name
        if not node_name:
            logging.warning("_pod_network_metrics: pod %s has no node_name", pod_name)
            return {}
        
        # Get stats summary from kubelet proxy
        summary = _read_node_stats_summary(node_name)
        logging.debug("_pod_network_metrics: summary keys=%r", list(summary.keys()) if summary else [])
        
        # Find the pod in the summary
        for pod_data in list(summary.get("pods") or []):
            pod_ref = dict(pod_data.get("podRef") or {})
            if str(pod_ref.get("namespace") or "") != namespace:
                continue
            if str(pod_ref.get("name") or "") != pod_name:
                continue
            
            logging.debug("_pod_network_metrics: found pod %s, pod_data keys=%r", pod_name, list(pod_data.keys()))
            
            # Network is a single object, not a list
            network = dict(pod_data.get("network") or {})
            logging.debug("_pod_network_metrics: network keys=%r", list(network.keys()))
            
            rx_value = _int_value(network.get("rxBytes"))
            tx_value = _int_value(network.get("txBytes"))
            
            if rx_value is not None or tx_value is not None:
                logging.debug("_pod_network_metrics: pod %s: rxBytes=%d, txBytes=%d", pod_name, rx_value or 0, tx_value or 0)
                return {
                    "rxBytes": rx_value,
                    "txBytes": tx_value,
                }
        
        logging.warning("_pod_network_metrics: pod %s not found in node %s stats summary", pod_name, node_name)
        return {}
    except ApiException as exc:
        logging.warning("_pod_network_metrics: ApiException status=%d, body=%r", exc.status, exc.body)
        if exc.status in {403, 404, 503}:
            return {}
        raise
    except Exception as exc:
        logging.error("_pod_network_metrics: exception=%s", exc)
        return {}
