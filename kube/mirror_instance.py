from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.instance_schema import (
    MirrorInstanceSpecModel,
    default_spec,
    default_parser_type,
    deep_merge,
    get_parser_contract,
    normalize_instance_dict,
)


GROUP = "auto-updater.miskler.ru"
VERSION = "v1alpha1"
PLURAL = "mirrorinstances"
KIND = "MirrorInstance"
API_VERSION = f"{GROUP}/{VERSION}"
APP_NAME = "auto-updater"
DEFAULT_NAMESPACE = "auto-updater"
DEFAULT_SPEC: dict[str, Any] = default_spec()


def utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def normalize_instance(instance: dict[str, Any]) -> dict[str, Any]:
    return normalize_instance_dict(instance)


def from_instance_dict(instance: dict[str, Any] | None) -> MirrorInstanceSpecModel:
    return MirrorInstanceSpecModel.from_instance_dict(instance)


def to_instance_dict(instance: dict[str, Any] | None, model: MirrorInstanceSpecModel) -> dict[str, Any]:
    normalized = deepcopy(dict(instance or {}))
    normalized["spec"] = model.to_spec_dict()
    return normalized


def instance_name(instance: dict[str, Any]) -> str:
    return str(instance.get("metadata", {}).get("name", ""))


def instance_namespace(instance: dict[str, Any]) -> str:
    return str(instance.get("metadata", {}).get("namespace", "") or DEFAULT_NAMESPACE)


def component_name(name: str, component: str) -> str:
    return f"{name}-{component}"


def workload_name(name: str, parser_type: str, workload_id: str) -> str:
    contract = get_parser_contract(parser_type)
    workload = contract.workloads_by_id[workload_id]
    return component_name(name, workload.name_suffix)


def workload_service_name(name: str, parser_type: str, workload_id: str) -> str:
    return workload_name(name, parser_type, workload_id)


def workload_service_url(name: str, namespace: str, parser_type: str, workload_id: str) -> str:
    return (
        f"http://{workload_service_name(name, parser_type, workload_id)}."
        f"{namespace}.svc.cluster.local:8080"
    )


def parser_name(name: str) -> str:
    return workload_name(name, default_parser_type(), "parser")


def runner_name(name: str) -> str:
    return workload_name(name, default_parser_type(), "steamcmd")


def parser_service_name(name: str) -> str:
    return workload_service_name(name, default_parser_type(), "parser")


def runner_service_name(name: str) -> str:
    return workload_service_name(name, default_parser_type(), "steamcmd")


def runner_config_secret_name(name: str) -> str:
    return component_name(name, "steamcmd-config")


def managed_credentials_secret_name(name: str) -> str:
    return component_name(name, "ow-credentials")


def managed_parser_proxy_secret_name(name: str) -> str:
    return component_name(name, "parser-proxies")


def managed_runner_proxy_secret_name(name: str) -> str:
    return component_name(name, "steamcmd-proxy")


@dataclass(frozen=True)
class ManagedSecretSpec:
    name: str
    namespace: str
    component: str
    labels: dict[str, str]
    owner_references: list[dict[str, Any]]


def managed_secret_names(name: str) -> set[str]:
    names = {managed_credentials_secret_name(name)}
    contract = get_parser_contract(default_parser_type())
    for secret_spec in contract.secret_specs:
        names.add(component_name(name, secret_spec.secret_component))
    return names


def managed_secret_specs(instance: dict[str, Any]) -> dict[str, ManagedSecretSpec]:
    normalized = normalize_instance(instance)
    name = instance_name(normalized)
    namespace = instance_namespace(normalized)
    refs = owner_reference(instance)
    specs = {
        "credentials": ManagedSecretSpec(
            name=managed_credentials_secret_name(name),
            namespace=namespace,
            component="credentials",
            labels={
                **common_labels(name, "credentials"),
                "auto-updater.miskler.ru/managed-secret": "true",
            },
            owner_references=refs,
        ),
    }
    model = from_instance_dict(normalized)
    contract = get_parser_contract(model.parser_type)
    for secret_spec in contract.secret_specs:
        specs[secret_spec.key] = ManagedSecretSpec(
            name=component_name(name, secret_spec.secret_component),
            namespace=namespace,
            component=secret_spec.secret_component,
            labels={
                **common_labels(name, secret_spec.secret_component),
                "auto-updater.miskler.ru/managed-secret": "true",
            },
            owner_references=refs,
        )
    if "parserProxyPoolSecretRef" in specs:
        specs["parser_proxy"] = specs["parserProxyPoolSecretRef"]
    if "runnerProxySecretRef" in specs:
        specs["runner_proxy"] = specs["runnerProxySecretRef"]
    return specs


def parser_service_url(name: str, namespace: str) -> str:
    return workload_service_url(name, namespace, default_parser_type(), "parser")


def runner_service_url(name: str, namespace: str) -> str:
    return workload_service_url(name, namespace, default_parser_type(), "steamcmd")


def common_labels(name: str, component: str | None = None) -> dict[str, str]:
    labels = {
        "app.kubernetes.io/name": APP_NAME,
        "app.kubernetes.io/part-of": APP_NAME,
        "app.kubernetes.io/managed-by": APP_NAME,
        "auto-updater.miskler.ru/instance": name,
    }
    if component:
        labels["app.kubernetes.io/component"] = component
    return labels


def owner_reference(instance: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = instance.get("metadata", {})
    uid = metadata.get("uid")
    if not uid:
        return []
    return [
        {
            "apiVersion": API_VERSION,
            "kind": KIND,
            "name": metadata.get("name"),
            "uid": uid,
            "controller": True,
            "blockOwnerDeletion": True,
        }
    ]


def set_condition(
    conditions: list[dict[str, Any]],
    condition_type: str,
    status: bool,
    reason: str,
    message: str,
) -> list[dict[str, Any]]:
    now = utcnow_iso()
    rendered_status = "True" if status else "False"
    other = [item for item in conditions if item.get("type") != condition_type]
    other.append(
        {
            "type": condition_type,
            "status": rendered_status,
            "reason": reason,
            "message": message,
            "lastTransitionTime": now,
        }
    )
    return other
