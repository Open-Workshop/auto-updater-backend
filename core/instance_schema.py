from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

DEFAULT_STORAGE_CLASS = "local-path"

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}


def deep_merge(base: dict[str, Any], override: Mapping[str, Any] | None) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _parse_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    lowered = str(value).strip().lower()
    if lowered in _TRUE_VALUES:
        return True
    if lowered in _FALSE_VALUES:
        return False
    return default


def _parse_int(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_float(value: Any, default: float) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class SyncFieldSpec:
    spec_key: str
    env_var: str
    config_attr: str
    form_field: str | None
    label: str
    value_type: str
    default: Any
    minimum: int | float | None = None
    required: bool = True

    def normalize(self, value: Any) -> Any:
        parsed = self._coerce(value, self.default)
        if self.minimum is not None and parsed < self.minimum:
            return self.minimum
        return parsed

    def parse_form(self, value: Any, fallback: Any) -> Any:
        if self.value_type == "bool":
            return self._coerce(value, False)
        rendered = str(value or "").strip()
        if not rendered:
            return fallback
        parsed = self._coerce(rendered, fallback)
        if self.minimum is not None and parsed < self.minimum:
            return fallback
        return parsed

    def validate_form(self, value: Any) -> str | None:
        if self.form_field is None or self.value_type not in {"int", "float"}:
            return None
        raw = str(value or "").strip()
        if not raw:
            if not self.required:
                return None
            return f"{self.label} is required"
        if self.value_type == "int":
            try:
                parsed = int(raw)
            except (TypeError, ValueError):
                return f"{self.label} must be an integer"
        else:
            try:
                parsed = float(raw)
            except (TypeError, ValueError):
                return f"{self.label} must be a number"
        if self.minimum is None or parsed >= self.minimum:
            return None
        if self.minimum <= 0:
            return f"{self.label} must be zero or greater"
        if self.value_type == "int":
            return f"{self.label} must be at least {int(self.minimum)}"
        return f"{self.label} must be at least {self.minimum}"

    def serialize_env(self, value: Any) -> str:
        normalized = self.normalize(value)
        if self.value_type == "bool":
            return "true" if normalized else "false"
        return str(normalized)

    def _coerce(self, value: Any, default: Any) -> Any:
        if self.value_type == "bool":
            return _parse_bool(value, bool(default))
        if self.value_type == "int":
            return _parse_int(value, int(default))
        if self.value_type == "float":
            return _parse_float(value, float(default))
        rendered = str(value or "").strip()
        return rendered or str(default)


SYNC_FIELD_SPECS: tuple[SyncFieldSpec, ...] = (
    SyncFieldSpec("apiBase", "OW_API_BASE", "api_base", "api_base", "API base", "str", "https://api.openworkshop.miskler.ru"),
    SyncFieldSpec("pageSize", "OW_PAGE_SIZE", "page_size", "page_size", "Page size", "int", 50),
    SyncFieldSpec("pollIntervalSeconds", "OW_POLL_INTERVAL", "poll_interval", "poll_interval_seconds", "Poll interval", "int", 10, minimum=1),
    SyncFieldSpec("timeoutSeconds", "OW_HTTP_TIMEOUT", "timeout", "timeout_seconds", "HTTP timeout", "int", 60, minimum=1),
    SyncFieldSpec("httpRetries", "OW_HTTP_RETRIES", "http_retries", "http_retries", "HTTP retries", "int", 3, minimum=0),
    SyncFieldSpec("httpRetryBackoff", "OW_HTTP_RETRY_BACKOFF", "http_retry_backoff", "http_retry_backoff", "HTTP retry backoff", "float", 5.0, minimum=0.0),
    SyncFieldSpec("runOnce", "OW_RUN_ONCE", "run_once", "run_once", "Run once", "bool", False),
    SyncFieldSpec("logLevel", "OW_LOG_LEVEL", "log_level", "log_level", "Log level", "str", "DEBUG"),
    SyncFieldSpec("logSteamRequests", "OW_LOG_STEAM_REQUESTS", "log_steam_requests", "log_steam_requests", "Log Steam requests", "bool", False),
    SyncFieldSpec("steamHttpRetries", "OW_STEAM_HTTP_RETRIES", "steam_http_retries", "steam_http_retries", "Steam HTTP retries", "int", 2, minimum=0),
    SyncFieldSpec("steamHttpBackoff", "OW_STEAM_HTTP_BACKOFF", "steam_http_backoff", "steam_http_backoff", "Steam HTTP backoff", "float", 2.0, minimum=0.0),
    SyncFieldSpec("steamRequestDelay", "OW_STEAM_REQUEST_DELAY", "steam_request_delay", "steam_request_delay", "Steam request delay", "float", 1.0, minimum=0.0),
    SyncFieldSpec("steamMaxPages", "OW_STEAM_MAX_PAGES", "steam_max_pages", "steam_max_pages", "Steam max pages", "int", 1000, minimum=0),
    SyncFieldSpec("steamStartPage", "OW_STEAM_START_PAGE", "steam_start_page", "steam_start_page", "Steam start page", "int", 1, minimum=1),
    SyncFieldSpec("steamMaxItems", "OW_STEAM_MAX_ITEMS", "steam_max_items", "steam_max_items", "Steam max items", "int", 0, minimum=0, required=False),
    SyncFieldSpec("steamDelay", "OW_STEAM_DELAY", "steam_delay", "steam_delay", "Steam page delay", "float", 1.0, minimum=0.0),
    SyncFieldSpec("maxScreenshots", "OW_MAX_SCREENSHOTS", "max_screenshots", "max_screenshots", "Max screenshots", "int", 20, minimum=0),
    SyncFieldSpec("uploadResourceFiles", "OW_RESOURCE_UPLOAD_FILES", "upload_resource_files", "upload_resource_files", "Upload resource files", "bool", True),
    SyncFieldSpec("scrapePreviewImages", "OW_SCRAPE_PREVIEW_IMAGES", "scrape_preview_images", "scrape_preview_images", "Scrape preview images", "bool", True),
    SyncFieldSpec("scrapeRequiredItems", "OW_SCRAPE_REQUIRED_ITEMS", "scrape_required_items", "scrape_required_items", "Scrape required items", "bool", True),
    SyncFieldSpec("forceRequiredItemId", "OW_FORCE_REQUIRED_ITEM_ID", "force_required_item_id", "force_required_item_id", "Forced required item", "str", ""),
    SyncFieldSpec("publicMode", "OW_MOD_PUBLIC", "public_mode", "public_mode", "Mod public mode", "int", 0, required=False),
    SyncFieldSpec("withoutAuthor", "OW_WITHOUT_AUTHOR", "without_author", "without_author", "Without author", "bool", False),
    SyncFieldSpec("syncTags", "OW_SYNC_TAGS", "sync_tags", "sync_tags", "Sync tags", "bool", True),
    SyncFieldSpec("pruneTags", "OW_PRUNE_TAGS", "prune_tags", "prune_tags", "Prune tags", "bool", True),
    SyncFieldSpec("syncDependencies", "OW_SYNC_DEPENDENCIES", "sync_dependencies", "sync_dependencies", "Sync dependencies", "bool", True),
    SyncFieldSpec("pruneDependencies", "OW_PRUNE_DEPENDENCIES", "prune_dependencies", "prune_dependencies", "Prune dependencies", "bool", True),
    SyncFieldSpec("syncResources", "OW_SYNC_RESOURCES", "sync_resources", "sync_resources", "Sync resources", "bool", True),
    SyncFieldSpec("pruneResources", "OW_PRUNE_RESOURCES", "prune_resources", "prune_resources", "Prune resources", "bool", True),
)

SYNC_FIELDS_BY_KEY = {field.spec_key: field for field in SYNC_FIELD_SPECS}
SYNC_FIELDS_BY_FORM = {
    field.form_field: field for field in SYNC_FIELD_SPECS if field.form_field is not None
}


def _merge_additive_unknown_keys(
    base: Mapping[str, Any],
    extra: Mapping[str, Any] | None,
    *,
    protected_keys: set[str],
) -> dict[str, Any]:
    merged = deepcopy(dict(base))
    for key, value in (extra or {}).items():
        if key in protected_keys:
            continue
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _merge_additive_unknown_keys(
                merged[key],
                value,
                protected_keys=set(),
            )
            continue
        merged[key] = deepcopy(value)
    return merged


def sync_defaults() -> dict[str, Any]:
    return {field.spec_key: deepcopy(field.default) for field in SYNC_FIELD_SPECS}


def default_spec() -> dict[str, Any]:
    return {
        "enabled": True,
        "source": {
            "steamAppId": 0,
            "owGameId": 0,
            "language": "english",
        },
        "sync": sync_defaults(),
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


@dataclass
class MirrorInstanceSpecModel:
    raw_spec: dict[str, Any]
    enabled: bool
    source: dict[str, Any]
    sync: dict[str, Any]
    sync_extras: dict[str, Any]
    credentials_secret_ref: str
    parser_proxy_pool_secret_ref: str
    runner_proxy_type: str
    runner_proxy_secret_ref: str
    storage: dict[str, dict[str, str]]

    @classmethod
    def from_spec_dict(cls, spec: Mapping[str, Any] | None) -> "MirrorInstanceSpecModel":
        raw_spec = deepcopy(dict(spec or {}))
        merged = deep_merge(default_spec(), raw_spec)
        merged_sync = dict(merged.get("sync") or {})
        sync = {field.spec_key: field.normalize(merged_sync.get(field.spec_key)) for field in SYNC_FIELD_SPECS}
        sync_extras = {
            key: deepcopy(value)
            for key, value in merged_sync.items()
            if key not in SYNC_FIELDS_BY_KEY
        }
        storage = dict(merged.get("storage") or {})
        parser_storage = dict(storage.get("parser") or {})
        runner_storage = dict(storage.get("runner") or {})
        return cls(
            raw_spec=raw_spec,
            enabled=bool(merged.get("enabled", True)),
            source={
                "steamAppId": _parse_int(
                    dict(merged.get("source") or {}).get("steamAppId"),
                    0,
                ),
                "owGameId": _parse_int(
                    dict(merged.get("source") or {}).get("owGameId"),
                    0,
                ),
                "language": str(
                    dict(merged.get("source") or {}).get("language", "english")
                ).strip()
                or "english",
            },
            sync=sync,
            sync_extras=sync_extras,
            credentials_secret_ref=str(
                dict(merged.get("credentials") or {}).get("secretRef") or ""
            ).strip(),
            parser_proxy_pool_secret_ref=str(
                dict(merged.get("parser") or {}).get("proxyPoolSecretRef") or ""
            ).strip(),
            runner_proxy_type=str(
                dict(dict(merged.get("steamcmd") or {}).get("proxy") or {}).get("type")
                or "socks5"
            ).strip()
            or "socks5",
            runner_proxy_secret_ref=str(
                dict(dict(merged.get("steamcmd") or {}).get("proxy") or {}).get("secretRef")
                or ""
            ).strip(),
            storage={
                "parser": {
                    "size": str(parser_storage.get("size") or "20Gi").strip() or "20Gi",
                    "storageClassName": str(
                        parser_storage.get("storageClassName") or DEFAULT_STORAGE_CLASS
                    ).strip()
                    or DEFAULT_STORAGE_CLASS,
                },
                "runner": {
                    "size": str(runner_storage.get("size") or "10Gi").strip() or "10Gi",
                    "storageClassName": str(
                        runner_storage.get("storageClassName") or DEFAULT_STORAGE_CLASS
                    ).strip()
                    or DEFAULT_STORAGE_CLASS,
                },
            },
        )

    @classmethod
    def from_instance_dict(
        cls,
        instance: Mapping[str, Any] | None,
    ) -> "MirrorInstanceSpecModel":
        if not isinstance(instance, Mapping):
            return cls.from_spec_dict(None)
        return cls.from_spec_dict(instance.get("spec"))

    def to_spec_dict(self) -> dict[str, Any]:
        spec = deep_merge(default_spec(), self.raw_spec)
        spec["enabled"] = bool(self.enabled)
        spec["source"] = deep_merge(
            dict(spec.get("source") or {}),
            self.source,
        )
        sync = deep_merge(dict(spec.get("sync") or {}), self.sync_extras)
        for field in SYNC_FIELD_SPECS:
            sync[field.spec_key] = deepcopy(self.sync[field.spec_key])
        spec["sync"] = sync
        spec["credentials"] = deep_merge(
            dict(spec.get("credentials") or {}),
            {"secretRef": self.credentials_secret_ref},
        )
        spec["parser"] = deep_merge(
            dict(spec.get("parser") or {}),
            {"proxyPoolSecretRef": self.parser_proxy_pool_secret_ref},
        )
        steamcmd = dict(spec.get("steamcmd") or {})
        steamcmd["proxy"] = deep_merge(
            dict(steamcmd.get("proxy") or {}),
            {
                "type": self.runner_proxy_type,
                "secretRef": self.runner_proxy_secret_ref,
            },
        )
        spec["steamcmd"] = steamcmd
        storage = dict(spec.get("storage") or {})
        storage["parser"] = deep_merge(
            dict(storage.get("parser") or {}),
            self.storage["parser"],
        )
        storage["runner"] = deep_merge(
            dict(storage.get("runner") or {}),
            self.storage["runner"],
        )
        spec["storage"] = storage
        return spec


def normalize_instance_dict(instance: Mapping[str, Any] | None) -> dict[str, Any]:
    normalized = deepcopy(dict(instance or {}))
    normalized["spec"] = MirrorInstanceSpecModel.from_instance_dict(instance).to_spec_dict()
    return normalized


def sync_form_values(sync: Mapping[str, Any] | None) -> dict[str, Any]:
    rendered_sync = dict(sync or {})
    values: dict[str, Any] = {}
    for field in SYNC_FIELD_SPECS:
        if field.form_field is None:
            continue
        values[field.form_field] = field.normalize(rendered_sync.get(field.spec_key))
    return values


def validate_sync_form_inputs(form: Mapping[str, Any]) -> dict[str, str]:
    errors: dict[str, str] = {}
    for field in SYNC_FIELD_SPECS:
        if field.form_field is None:
            continue
        message = field.validate_form(form.get(field.form_field))
        if message:
            errors[field.form_field] = message
    return errors


def build_sync_spec_from_form(
    base_sync: Mapping[str, Any] | None,
    form: Mapping[str, Any],
    raw_patch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    current = dict(base_sync or {})
    sync = deep_merge(sync_defaults(), current)
    for field in SYNC_FIELD_SPECS:
        if field.form_field is None:
            continue
        sync[field.spec_key] = field.parse_form(
            form.get(field.form_field),
            field.normalize(sync.get(field.spec_key)),
        )
    return _merge_additive_unknown_keys(
        sync,
        raw_patch,
        protected_keys=set(SYNC_FIELDS_BY_KEY),
    )


def sync_form_minimum(form_field: str) -> str:
    field = SYNC_FIELDS_BY_FORM.get(form_field)
    if field is None or field.minimum is None:
        return ""
    return str(field.minimum)


def iter_sync_env_items(sync: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    rendered_sync = dict(sync or {})
    return [
        (field.env_var, field.serialize_env(rendered_sync.get(field.spec_key)))
        for field in SYNC_FIELD_SPECS
    ]


def load_sync_config_from_env(environ: Mapping[str, str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field in SYNC_FIELD_SPECS:
        values[field.config_attr] = field.normalize(environ.get(field.env_var))
    return values
