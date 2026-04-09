from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Mapping


DEFAULT_PARSER_TYPE = "steam-workshop"
DEFAULT_STORAGE_CLASS = "local-path"

_TRUE_VALUES = {"1", "true", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}


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
class ParserConfigFieldSpec:
    key: str
    env_var: str
    config_attr: str
    form_field: str | None
    label: str
    value_type: str
    default: Any
    minimum: int | float | None = None
    required: bool = True
    ui_section: str = "advanced"
    options: tuple[tuple[str, str], ...] = ()
    step: str = ""
    hint: str = ""

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

    def input_type(self) -> str:
        if self.value_type == "bool":
            return "checkbox"
        if self.options:
            return "select"
        if self.value_type in {"int", "float"}:
            return "number"
        return "text"

    def _coerce(self, value: Any, default: Any) -> Any:
        if self.value_type == "bool":
            return _parse_bool(value, bool(default))
        if self.value_type == "int":
            return _parse_int(value, int(default))
        if self.value_type == "float":
            return _parse_float(value, float(default))
        rendered = str(value or "").strip()
        return rendered or str(default)


@dataclass(frozen=True)
class ParserSecretSpec:
    key: str
    label: str
    form_field: str
    secret_component: str
    secret_data_key: str
    input_type: str = "textarea"
    hint: str = ""
    required: bool = False


@dataclass(frozen=True)
class WorkloadLogTargetSpec:
    target: str
    label: str
    container_name: str


@dataclass(frozen=True)
class ParserWorkloadSpec:
    workload_id: str
    component: str
    name_suffix: str
    display_label: str
    mode: str
    main_container_name: str
    storage_form_field: str
    storage_label: str
    default_storage_size: str
    default_storage_class: str = DEFAULT_STORAGE_CLASS
    config_fields: tuple[ParserConfigFieldSpec, ...] = ()
    log_targets: tuple[WorkloadLogTargetSpec, ...] = ()
    service_enabled: bool = True


@dataclass(frozen=True)
class ParserContract:
    parser_type: str
    label: str
    description: str
    config_fields: tuple[ParserConfigFieldSpec, ...]
    secret_specs: tuple[ParserSecretSpec, ...]
    workloads: tuple[ParserWorkloadSpec, ...]
    overview_config_keys: tuple[str, ...] = ()
    subtitle_config_keys: tuple[str, ...] = ()
    config_fields_by_key: dict[str, ParserConfigFieldSpec] = field(init=False)
    config_fields_by_form: dict[str, ParserConfigFieldSpec] = field(init=False)
    secret_specs_by_key: dict[str, ParserSecretSpec] = field(init=False)
    secret_specs_by_form: dict[str, ParserSecretSpec] = field(init=False)
    workloads_by_id: dict[str, ParserWorkloadSpec] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "config_fields_by_key",
            {field.key: field for field in self.config_fields},
        )
        object.__setattr__(
            self,
            "config_fields_by_form",
            {field.form_field: field for field in self.config_fields if field.form_field},
        )
        object.__setattr__(
            self,
            "secret_specs_by_key",
            {spec.key: spec for spec in self.secret_specs},
        )
        object.__setattr__(
            self,
            "secret_specs_by_form",
            {spec.form_field: spec for spec in self.secret_specs},
        )
        object.__setattr__(
            self,
            "workloads_by_id",
            {workload.workload_id: workload for workload in self.workloads},
        )


STEAM_WORKSHOP_CONFIG_FIELDS: tuple[ParserConfigFieldSpec, ...] = (
    ParserConfigFieldSpec("steamAppId", "OW_STEAM_APP_ID", "steam_app_id", "steam_app_id", "Steam App ID", "int", 0, minimum=1, ui_section="basic"),
    ParserConfigFieldSpec("owGameId", "OW_GAME_ID", "game_id", "ow_game_id", "OW Game ID", "int", 0, minimum=0, required=False, ui_section="basic"),
    ParserConfigFieldSpec("language", "STEAM_LANGUAGE", "language", "language", "Language", "str", "english", required=False, ui_section="basic"),
    ParserConfigFieldSpec("apiBase", "OW_API_BASE", "api_base", "api_base", "API base", "str", "https://api.openworkshop.miskler.ru", required=False),
    ParserConfigFieldSpec("pageSize", "OW_PAGE_SIZE", "page_size", "page_size", "Page size", "int", 50),
    ParserConfigFieldSpec("pollIntervalSeconds", "OW_POLL_INTERVAL", "poll_interval", "poll_interval_seconds", "Poll interval", "int", 10, minimum=1),
    ParserConfigFieldSpec("timeoutSeconds", "OW_HTTP_TIMEOUT", "timeout", "timeout_seconds", "HTTP timeout", "int", 60, minimum=1),
    ParserConfigFieldSpec("httpRetries", "OW_HTTP_RETRIES", "http_retries", "http_retries", "HTTP retries", "int", 3, minimum=0),
    ParserConfigFieldSpec("httpRetryBackoff", "OW_HTTP_RETRY_BACKOFF", "http_retry_backoff", "http_retry_backoff", "HTTP retry backoff", "float", 5.0, minimum=0.0, step="0.1"),
    ParserConfigFieldSpec("runOnce", "OW_RUN_ONCE", "run_once", "run_once", "Run once", "bool", False, ui_section="toggle"),
    ParserConfigFieldSpec("logLevel", "OW_LOG_LEVEL", "log_level", "log_level", "Log level", "str", "DEBUG", required=False, options=(("DEBUG", "DEBUG"), ("INFO", "INFO"), ("WARNING", "WARNING"), ("ERROR", "ERROR"))),
    ParserConfigFieldSpec("logSteamRequests", "OW_LOG_STEAM_REQUESTS", "log_steam_requests", "log_steam_requests", "Log Steam requests", "bool", False, ui_section="toggle"),
    ParserConfigFieldSpec("steamHttpRetries", "OW_STEAM_HTTP_RETRIES", "steam_http_retries", "steam_http_retries", "Steam HTTP retries", "int", 2, minimum=0),
    ParserConfigFieldSpec("steamHttpBackoff", "OW_STEAM_HTTP_BACKOFF", "steam_http_backoff", "steam_http_backoff", "Steam HTTP backoff", "float", 2.0, minimum=0.0, step="0.1"),
    ParserConfigFieldSpec("steamRequestDelay", "OW_STEAM_REQUEST_DELAY", "steam_request_delay", "steam_request_delay", "Steam request delay", "float", 1.0, minimum=0.0, step="0.1"),
    ParserConfigFieldSpec("steamMaxPages", "OW_STEAM_MAX_PAGES", "steam_max_pages", "steam_max_pages", "Steam max pages", "int", 1000, minimum=0),
    ParserConfigFieldSpec("steamStartPage", "OW_STEAM_START_PAGE", "steam_start_page", "steam_start_page", "Steam start page", "int", 1, minimum=1),
    ParserConfigFieldSpec("steamMaxItems", "OW_STEAM_MAX_ITEMS", "steam_max_items", "steam_max_items", "Steam max items", "int", 0, minimum=0, required=False),
    ParserConfigFieldSpec("steamDelay", "OW_STEAM_DELAY", "steam_delay", "steam_delay", "Steam page delay", "float", 1.0, minimum=0.0, step="0.1"),
    ParserConfigFieldSpec("maxScreenshots", "OW_MAX_SCREENSHOTS", "max_screenshots", "max_screenshots", "Max screenshots", "int", 20, minimum=0),
    ParserConfigFieldSpec("uploadResourceFiles", "OW_RESOURCE_UPLOAD_FILES", "upload_resource_files", "upload_resource_files", "Upload resource files", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("scrapePreviewImages", "OW_SCRAPE_PREVIEW_IMAGES", "scrape_preview_images", "scrape_preview_images", "Scrape preview images", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("scrapeRequiredItems", "OW_SCRAPE_REQUIRED_ITEMS", "scrape_required_items", "scrape_required_items", "Scrape required items", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("forceRequiredItemId", "OW_FORCE_REQUIRED_ITEM_ID", "force_required_item_id", "force_required_item_id", "Forced required item", "str", "", required=False),
    ParserConfigFieldSpec("publicMode", "OW_MOD_PUBLIC", "public_mode", "public_mode", "Mod public mode", "int", 0, required=False),
    ParserConfigFieldSpec("withoutAuthor", "OW_WITHOUT_AUTHOR", "without_author", "without_author", "Without author", "bool", False, ui_section="toggle"),
    ParserConfigFieldSpec("syncTags", "OW_SYNC_TAGS", "sync_tags", "sync_tags", "Sync tags", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("pruneTags", "OW_PRUNE_TAGS", "prune_tags", "prune_tags", "Prune tags", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("syncDependencies", "OW_SYNC_DEPENDENCIES", "sync_dependencies", "sync_dependencies", "Sync dependencies", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("pruneDependencies", "OW_PRUNE_DEPENDENCIES", "prune_dependencies", "prune_dependencies", "Prune dependencies", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("syncResources", "OW_SYNC_RESOURCES", "sync_resources", "sync_resources", "Sync resources", "bool", True, ui_section="toggle"),
    ParserConfigFieldSpec("pruneResources", "OW_PRUNE_RESOURCES", "prune_resources", "prune_resources", "Prune resources", "bool", True, ui_section="toggle"),
)

STEAM_WORKSHOP_SECRET_SPECS: tuple[ParserSecretSpec, ...] = (
    ParserSecretSpec(
        key="parserProxyPoolSecretRef",
        label="Parser proxy pool",
        form_field="parser_proxy_pool",
        secret_component="parser-proxies",
        secret_data_key="proxyPool",
        input_type="textarea",
        hint="One proxy URL per line, or comma-separated. This pool is used only by parser HTTP requests.",
    ),
    ParserSecretSpec(
        key="runnerProxySecretRef",
        label="Runner proxy URL",
        form_field="runner_proxy_url",
        secret_component="steamcmd-proxy",
        secret_data_key="proxyUrl",
        input_type="textarea",
        hint="Single upstream proxy used by the helper workload through the TUN sidecar.",
    ),
)

STEAM_WORKSHOP_WORKLOADS: tuple[ParserWorkloadSpec, ...] = (
    ParserWorkloadSpec(
        workload_id="parser",
        component="parser",
        name_suffix="parser",
        display_label="Parser",
        mode="parser",
        main_container_name="parser",
        storage_form_field="parser_storage_size",
        storage_label="Parser PVC size",
        default_storage_size="20Gi",
        log_targets=(WorkloadLogTargetSpec("parser", "Parser", "parser"),),
    ),
    ParserWorkloadSpec(
        workload_id="steamcmd",
        component="runner",
        name_suffix="steamcmd",
        display_label="Runner",
        mode="runner",
        main_container_name="runner",
        storage_form_field="runner_storage_size",
        storage_label="Runner PVC size",
        default_storage_size="10Gi",
        config_fields=(
            ParserConfigFieldSpec(
                "proxyType",
                "",
                "runner_proxy_type",
                "runner_proxy_type",
                "Runner proxy type",
                "str",
                "socks5",
                required=False,
                ui_section="workload",
                options=(("socks5", "SOCKS5"), ("http", "HTTP")),
            ),
        ),
        log_targets=(
            WorkloadLogTargetSpec("steamcmd", "Runner", "runner"),
            WorkloadLogTargetSpec("steamcmd:tun-proxy", "TUN", "tun-proxy"),
        ),
    ),
)

STEAM_WORKSHOP_CONTRACT = ParserContract(
    parser_type=DEFAULT_PARSER_TYPE,
    label="Steam Workshop",
    description="Mirror Steam Workshop content into Open Workshop.",
    config_fields=STEAM_WORKSHOP_CONFIG_FIELDS,
    secret_specs=STEAM_WORKSHOP_SECRET_SPECS,
    workloads=STEAM_WORKSHOP_WORKLOADS,
    overview_config_keys=("steamAppId", "owGameId", "language"),
    subtitle_config_keys=("steamAppId", "owGameId"),
)

_PARSER_REGISTRY: dict[str, ParserContract] = {
    STEAM_WORKSHOP_CONTRACT.parser_type: STEAM_WORKSHOP_CONTRACT,
}


def parser_type_options() -> list[tuple[str, str]]:
    return [(item.parser_type, item.label) for item in _PARSER_REGISTRY.values()]


def default_parser_type() -> str:
    return DEFAULT_PARSER_TYPE


def get_parser_contract(parser_type: str | None) -> ParserContract:
    normalized = str(parser_type or "").strip() or DEFAULT_PARSER_TYPE
    try:
        return _PARSER_REGISTRY[normalized]
    except KeyError as exc:
        raise KeyError(f"unknown parser type: {normalized}") from exc


def parser_config_defaults(parser_type: str | None = None) -> dict[str, Any]:
    contract = get_parser_contract(parser_type)
    return {field.key: deepcopy(field.default) for field in contract.config_fields}


def parser_secret_ref_defaults(parser_type: str | None = None) -> dict[str, str]:
    contract = get_parser_contract(parser_type)
    return {field.key: "" for field in contract.secret_specs}


def parser_workload_defaults(parser_type: str | None = None) -> dict[str, dict[str, Any]]:
    contract = get_parser_contract(parser_type)
    return {
        workload.workload_id: {
            "storage": {
                "size": workload.default_storage_size,
                "storageClassName": workload.default_storage_class,
            },
            "config": {
                field.key: deepcopy(field.default)
                for field in workload.config_fields
            },
        }
        for workload in contract.workloads
    }


def parser_overview_pairs(parser_type: str | None, config: Mapping[str, Any]) -> list[tuple[str, str]]:
    contract = get_parser_contract(parser_type)
    rendered = dict(config or {})
    pairs: list[tuple[str, str]] = []
    for key in contract.overview_config_keys:
        field = contract.config_fields_by_key.get(key)
        if field is None:
            continue
        pairs.append((field.label, str(field.normalize(rendered.get(key)))))
    return pairs


def parser_subtitle(parser_type: str | None, config: Mapping[str, Any]) -> str:
    contract = get_parser_contract(parser_type)
    rendered = dict(config or {})
    parts: list[str] = []
    for key in contract.subtitle_config_keys:
        field = contract.config_fields_by_key.get(key)
        if field is None:
            continue
        value = field.normalize(rendered.get(key))
        if key == "steamAppId":
            parts.append(f"Steam {value}")
        elif key == "owGameId":
            parts.append(f"OW {value}")
        else:
            parts.append(f"{field.label} {value}")
    return " · ".join(parts)
