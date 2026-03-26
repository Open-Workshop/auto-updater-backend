from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any


GROUP = "auto-updater.miskler.ru"
VERSION = "v1alpha1"
PLURAL = "mirrorinstances"
KIND = "MirrorInstance"
API_VERSION = f"{GROUP}/{VERSION}"
APP_NAME = "auto-updater"
DEFAULT_NAMESPACE = "auto-updater"
DEFAULT_STORAGE_CLASS = "local-path"

DEFAULT_SPEC: dict[str, Any] = {
    "enabled": True,
    "source": {
        "steamAppId": 0,
        "owGameId": 0,
        "language": "english",
    },
    "sync": {
        "apiBase": "https://api.openworkshop.miskler.ru",
        "pageSize": 50,
        "pollIntervalSeconds": 10,
        "timeoutSeconds": 60,
        "httpRetries": 3,
        "httpRetryBackoff": 5.0,
        "runOnce": False,
        "logLevel": "DEBUG",
        "logSteamRequests": False,
        "steamHttpRetries": 2,
        "steamHttpBackoff": 2.0,
        "steamRequestDelay": 1.0,
        "steamMaxPages": 1000,
        "steamStartPage": 1,
        "steamMaxItems": 0,
        "steamDelay": 1.0,
        "maxScreenshots": 20,
        "uploadResourceFiles": True,
        "scrapePreviewImages": True,
        "scrapeRequiredItems": True,
        "forceRequiredItemId": "",
        "publicMode": 0,
        "withoutAuthor": False,
        "syncTags": True,
        "pruneTags": True,
        "syncDependencies": True,
        "pruneDependencies": True,
        "syncResources": True,
        "pruneResources": True,
    },
    "credentials": {
        "secretRef": "",
    },
    "parser": {
        "proxyPoolSecretRef": "",
    },
    "steamcmd": {
        "proxy": {
            "type": "socks5",
            "secretRef": "",
        }
    },
    "storage": {
        "parser": {
            "size": "20Gi",
            "storageClassName": DEFAULT_STORAGE_CLASS,
        },
        "runner": {
            "size": "10Gi",
            "storageClassName": DEFAULT_STORAGE_CLASS,
        },
    },
}


def utcnow_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def normalize_instance(instance: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(instance)
    normalized["spec"] = deep_merge(DEFAULT_SPEC, dict(instance.get("spec") or {}))
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
