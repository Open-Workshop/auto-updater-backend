from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from core.instance_schema import (
    MirrorInstanceSpecModel,
    default_spec,
    deep_merge,
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


def parser_name(name: str) -> str:
    return component_name(name, "parser")


def runner_name(name: str) -> str:
    return component_name(name, "steamcmd")


def parser_service_name(name: str) -> str:
    return parser_name(name)


def runner_service_name(name: str) -> str:
    return runner_name(name)


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
    return {
        managed_credentials_secret_name(name),
        managed_parser_proxy_secret_name(name),
        managed_runner_proxy_secret_name(name),
    }


def managed_secret_specs(instance: dict[str, Any]) -> dict[str, ManagedSecretSpec]:
    normalized = normalize_instance(instance)
    name = instance_name(normalized)
    namespace = instance_namespace(normalized)
    refs = owner_reference(instance)
    return {
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
        "parser_proxy": ManagedSecretSpec(
            name=managed_parser_proxy_secret_name(name),
            namespace=namespace,
            component="parser-proxies",
            labels={
                **common_labels(name, "parser-proxies"),
                "auto-updater.miskler.ru/managed-secret": "true",
            },
            owner_references=refs,
        ),
        "runner_proxy": ManagedSecretSpec(
            name=managed_runner_proxy_secret_name(name),
            namespace=namespace,
            component="runner-proxy",
            labels={
                **common_labels(name, "runner-proxy"),
                "auto-updater.miskler.ru/managed-secret": "true",
            },
            owner_references=refs,
        ),
    }


def parser_service_url(name: str, namespace: str) -> str:
    return f"http://{parser_service_name(name)}.{namespace}.svc.cluster.local:8080"


def runner_service_url(name: str, namespace: str) -> str:
    return f"http://{runner_service_name(name)}.{namespace}.svc.cluster.local:8080"


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
