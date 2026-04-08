from __future__ import annotations

import json
from typing import Any

from core.http_utils import ParsedProxy, parse_proxy_url
from kube.mirror_instance import (
    common_labels,
    instance_name,
    instance_namespace,
    normalize_instance,
    owner_reference,
    parser_name,
    parser_service_name,
    runner_service_url,
    runner_config_secret_name,
    runner_name,
    runner_service_name,
)


PARSER_SERVICE_ACCOUNT_NAME = "auto-updater-parser"


def _stringify_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def _env(name: str, value: Any) -> dict[str, Any]:
    return {"name": name, "value": str(value)}


def _secret_env(name: str, secret_name: str, key: str, *, optional: bool = False) -> dict[str, Any]:
    return {
        "name": name,
        "valueFrom": {
            "secretKeyRef": {
                "name": secret_name,
                "key": key,
                "optional": optional,
            }
        },
    }


def _storage_size(spec: dict[str, Any], component: str) -> str:
    return str(spec["storage"][component]["size"])


def _storage_class(spec: dict[str, Any], component: str) -> str | None:
    value = str(spec["storage"][component].get("storageClassName") or "").strip()
    return value or None


def _sync_value(spec: dict[str, Any], key: str) -> Any:
    return spec["sync"][key]


def build_parser_service(instance: dict[str, Any]) -> dict[str, Any]:
    name = instance_name(instance)
    namespace = instance_namespace(instance)
    labels = common_labels(name, "parser")
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": parser_service_name(name),
            "namespace": namespace,
            "labels": labels,
            "ownerReferences": owner_reference(instance),
        },
        "spec": {
            "selector": labels,
            "ports": [
                {
                    "name": "http",
                    "port": 8080,
                    "targetPort": 8080,
                }
            ],
        },
    }


def build_runner_service(instance: dict[str, Any]) -> dict[str, Any]:
    name = instance_name(instance)
    namespace = instance_namespace(instance)
    labels = common_labels(name, "runner")
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": runner_service_name(name),
            "namespace": namespace,
            "labels": labels,
            "ownerReferences": owner_reference(instance),
        },
        "spec": {
            "selector": labels,
            "ports": [
                {
                    "name": "http",
                    "port": 8080,
                    "targetPort": 8080,
                }
            ],
        },
    }


def build_parser_env(instance: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = normalize_instance(instance)
    name = instance_name(normalized)
    namespace = instance_namespace(normalized)
    spec = normalized["spec"]
    credentials_secret = spec["credentials"]["secretRef"]
    parser_proxy_secret = spec["parser"].get("proxyPoolSecretRef", "")
    env = [
        _secret_env("OW_LOGIN", credentials_secret, "login"),
        _secret_env("OW_PASSWORD", credentials_secret, "password"),
        _env("OW_API_BASE", _sync_value(spec, "apiBase")),
        _env("OW_STEAM_APP_ID", spec["source"].get("steamAppId", 0)),
        _env("OW_GAME_ID", spec["source"].get("owGameId", 0)),
        _env("STEAM_LANGUAGE", spec["source"].get("language", "english")),
        _env("OW_MIRROR_DIR", "/data/mirror"),
        _env("STEAM_ROOT", "/data/steam"),
        _env("OW_PAGE_SIZE", _sync_value(spec, "pageSize")),
        _env("OW_POLL_INTERVAL", _sync_value(spec, "pollIntervalSeconds")),
        _env("OW_HTTP_TIMEOUT", _sync_value(spec, "timeoutSeconds")),
        _env("OW_HTTP_RETRIES", _sync_value(spec, "httpRetries")),
        _env("OW_HTTP_RETRY_BACKOFF", _sync_value(spec, "httpRetryBackoff")),
        _env("OW_RUN_ONCE", _stringify_bool(_sync_value(spec, "runOnce"))),
        _env("OW_LOG_LEVEL", _sync_value(spec, "logLevel")),
        _env("OW_LOG_STEAM_REQUESTS", _stringify_bool(_sync_value(spec, "logSteamRequests"))),
        _env("OW_STEAM_HTTP_RETRIES", _sync_value(spec, "steamHttpRetries")),
        _env("OW_STEAM_HTTP_BACKOFF", _sync_value(spec, "steamHttpBackoff")),
        _env("OW_STEAM_REQUEST_DELAY", _sync_value(spec, "steamRequestDelay")),
        _env("OW_STEAM_PROXY_SCOPE", "mod_pages" if parser_proxy_secret else "none"),
        _env("OW_STEAM_MAX_PAGES", _sync_value(spec, "steamMaxPages")),
        _env("OW_STEAM_START_PAGE", _sync_value(spec, "steamStartPage")),
        _env("OW_STEAM_MAX_ITEMS", _sync_value(spec, "steamMaxItems")),
        _env("OW_STEAM_DELAY", _sync_value(spec, "steamDelay")),
        _env("OW_MAX_SCREENSHOTS", _sync_value(spec, "maxScreenshots")),
        _env("OW_RESOURCE_UPLOAD_FILES", _stringify_bool(_sync_value(spec, "uploadResourceFiles"))),
        _env("OW_SCRAPE_PREVIEW_IMAGES", _stringify_bool(_sync_value(spec, "scrapePreviewImages"))),
        _env("OW_SCRAPE_REQUIRED_ITEMS", _stringify_bool(_sync_value(spec, "scrapeRequiredItems"))),
        _env("OW_FORCE_REQUIRED_ITEM_ID", _sync_value(spec, "forceRequiredItemId")),
        _env("OW_MOD_PUBLIC", _sync_value(spec, "publicMode")),
        _env("OW_WITHOUT_AUTHOR", _stringify_bool(_sync_value(spec, "withoutAuthor"))),
        _env("OW_SYNC_TAGS", _stringify_bool(_sync_value(spec, "syncTags"))),
        _env("OW_PRUNE_TAGS", _stringify_bool(_sync_value(spec, "pruneTags"))),
        _env("OW_SYNC_DEPENDENCIES", _stringify_bool(_sync_value(spec, "syncDependencies"))),
        _env("OW_PRUNE_DEPENDENCIES", _stringify_bool(_sync_value(spec, "pruneDependencies"))),
        _env("OW_SYNC_RESOURCES", _stringify_bool(_sync_value(spec, "syncResources"))),
        _env("OW_PRUNE_RESOURCES", _stringify_bool(_sync_value(spec, "pruneResources"))),
        _env("OW_STEAMCMD_RUNNER_URL", runner_service_url(name, namespace)),
        _env("OW_ADMIN_HOST", "0.0.0.0"),
        _env("OW_ADMIN_PORT", "8080"),
        _env("OW_INSTANCE_NAME", name),
        _env("OW_INSTANCE_NAMESPACE", namespace),
    ]
    if parser_proxy_secret:
        env.append(_secret_env("OW_STEAM_PROXY_POOL", parser_proxy_secret, "proxyPool", optional=True))
    return env


def build_parser_statefulset(instance: dict[str, Any], app_image: str) -> dict[str, Any]:
    normalized = normalize_instance(instance)
    name = instance_name(normalized)
    namespace = instance_namespace(normalized)
    spec = normalized["spec"]
    labels = common_labels(name, "parser")
    replicas = 1 if spec.get("enabled", True) else 0
    claim_spec: dict[str, Any] = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": _storage_size(spec, "parser")}},
    }
    storage_class = _storage_class(spec, "parser")
    if storage_class:
        claim_spec["storageClassName"] = storage_class
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": parser_name(name),
            "namespace": namespace,
            "labels": labels,
            "ownerReferences": owner_reference(instance),
        },
        "spec": {
            "serviceName": parser_service_name(name),
            "replicas": replicas,
            "persistentVolumeClaimRetentionPolicy": {
                "whenDeleted": "Delete",
                "whenScaled": "Delete",
            },
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "serviceAccountName": PARSER_SERVICE_ACCOUNT_NAME,
                    "containers": [
                        {
                            "name": "parser",
                            "image": app_image,
                            "imagePullPolicy": "IfNotPresent",
                            "args": ["parser"],
                            "ports": [{"name": "http", "containerPort": 8080}],
                            "env": build_parser_env(instance),
                            "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                            "readinessProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "initialDelaySeconds": 5,
                                "periodSeconds": 10,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "initialDelaySeconds": 15,
                                "periodSeconds": 20,
                            },
                        }
                    ],
                },
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": claim_spec,
                }
            ],
        },
    }


def _proxy_outbound(proxy: ParsedProxy) -> dict[str, Any]:
    outbound: dict[str, Any] = {
        "tag": "proxy",
        "server": proxy.host,
        "server_port": proxy.port,
    }
    if proxy.is_socks:
        outbound["type"] = "socks"
        outbound["version"] = "5"
    else:
        outbound["type"] = "http"
    if proxy.username:
        outbound["username"] = proxy.username
    if proxy.password:
        outbound["password"] = proxy.password
    return outbound


def render_singbox_config(proxy_url: str, proxy_type: str) -> str:
    parsed = parse_proxy_url(proxy_url)
    expected_type = (proxy_type or "").strip().lower()
    if expected_type == "socks5" and not parsed.is_socks:
        raise ValueError("steamcmd proxy is configured as socks5, but secret URL is not socks5")
    if expected_type == "http" and not parsed.is_http:
        raise ValueError("steamcmd proxy is configured as http, but secret URL is not http")
    payload = {
        "log": {"level": "info"},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
            }
        ],
        "outbounds": [
            _proxy_outbound(parsed),
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": [
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": [".svc.cluster.local"], "outbound": "direct"},
                {"domain_suffix": [".cluster.local"], "outbound": "direct"},
            ],
            "final": "proxy",
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def build_runner_config_secret(
    instance: dict[str, Any],
    upstream_proxy_url: str,
) -> dict[str, Any]:
    normalized = normalize_instance(instance)
    name = instance_name(normalized)
    namespace = instance_namespace(normalized)
    spec = normalized["spec"]
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": runner_config_secret_name(name),
            "namespace": namespace,
            "labels": common_labels(name, "runner-config"),
            "ownerReferences": owner_reference(instance),
        },
        "type": "Opaque",
        "stringData": {
            "config.json": render_singbox_config(
                upstream_proxy_url,
                str(spec["steamcmd"]["proxy"].get("type", "socks5")),
            )
        },
    }


def build_runner_statefulset(
    instance: dict[str, Any],
    app_image: str,
    singbox_image: str,
) -> dict[str, Any]:
    normalized = normalize_instance(instance)
    name = instance_name(normalized)
    namespace = instance_namespace(normalized)
    spec = normalized["spec"]
    labels = common_labels(name, "runner")
    replicas = 1 if spec.get("enabled", True) else 0
    claim_spec: dict[str, Any] = {
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": _storage_size(spec, "runner")}},
    }
    storage_class = _storage_class(spec, "runner")
    if storage_class:
        claim_spec["storageClassName"] = storage_class
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": runner_name(name),
            "namespace": namespace,
            "labels": labels,
            "ownerReferences": owner_reference(instance),
        },
        "spec": {
            "serviceName": runner_service_name(name),
            "replicas": replicas,
            "persistentVolumeClaimRetentionPolicy": {
                "whenDeleted": "Delete",
                "whenScaled": "Delete",
            },
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "securityContext": {"fsGroup": 1000},
                    "volumes": [
                        {
                            "name": "runner-config",
                            "secret": {"secretName": runner_config_secret_name(name)},
                        },
                        {
                            "name": "dev-tun",
                            "hostPath": {"path": "/dev/net/tun", "type": "CharDevice"},
                        },
                    ],
                    "containers": [
                        {
                            "name": "runner",
                            "image": app_image,
                            "imagePullPolicy": "IfNotPresent",
                            "args": ["runner"],
                            "ports": [{"name": "http", "containerPort": 8080}],
                            "env": [
                                _env("RUNNER_BIND_HOST", "0.0.0.0"),
                                _env("RUNNER_BIND_PORT", "8080"),
                                _env("STEAM_ROOT", "/data/steam"),
                                _env("DEPOTDOWNLOADER_PATH", "/opt/depotdownloader/DepotDownloader"),
                            ],
                            "volumeMounts": [{"name": "data", "mountPath": "/data"}],
                            "readinessProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "initialDelaySeconds": 5,
                                "periodSeconds": 10,
                            },
                            "livenessProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "initialDelaySeconds": 15,
                                "periodSeconds": 20,
                            },
                        },
                        {
                            "name": "tun-proxy",
                            "image": singbox_image,
                            "imagePullPolicy": "IfNotPresent",
                            "args": ["run", "-c", "/config/config.json"],
                            "securityContext": {
                                "runAsUser": 0,
                                "capabilities": {"add": ["NET_ADMIN"]},
                            },
                            "volumeMounts": [
                                {
                                    "name": "runner-config",
                                    "mountPath": "/config",
                                    "readOnly": True,
                                },
                                {
                                    "name": "dev-tun",
                                    "mountPath": "/dev/net/tun",
                                },
                            ],
                        },
                    ],
                },
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": claim_spec,
                }
            ],
        },
    }
