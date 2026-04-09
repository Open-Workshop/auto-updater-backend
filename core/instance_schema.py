from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from core.parser_registry import (
    DEFAULT_PARSER_TYPE,
    DEFAULT_STORAGE_CLASS,
    ParserConfigFieldSpec,
    ParserContract,
    default_parser_type,
    get_parser_contract,
    parser_config_defaults,
    parser_secret_ref_defaults,
    parser_subtitle,
    parser_type_options,
    parser_workload_defaults,
)


LEGACY_SYNC_FIELD_KEYS = {
    "apiBase",
    "pageSize",
    "pollIntervalSeconds",
    "timeoutSeconds",
    "httpRetries",
    "httpRetryBackoff",
    "runOnce",
    "logLevel",
    "logSteamRequests",
    "steamHttpRetries",
    "steamHttpBackoff",
    "steamRequestDelay",
    "steamMaxPages",
    "steamStartPage",
    "steamMaxItems",
    "steamDelay",
    "maxScreenshots",
    "uploadResourceFiles",
    "scrapePreviewImages",
    "scrapeRequiredItems",
    "forceRequiredItemId",
    "publicMode",
    "withoutAuthor",
    "syncTags",
    "pruneTags",
    "syncDependencies",
    "pruneDependencies",
    "syncResources",
    "pruneResources",
}


def deep_merge(base: dict[str, Any], override: Mapping[str, Any] | None) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _parse_int(value: Any, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _unknown_top_level_fields(raw_spec: Mapping[str, Any]) -> dict[str, Any]:
    known = {
        "enabled",
        "credentials",
        "parser",
        "source",
        "sync",
        "steamcmd",
        "storage",
    }
    return {
        key: deepcopy(value)
        for key, value in raw_spec.items()
        if key not in known
    }


def _merge_additive_unknown_keys(
    base: dict[str, Any],
    extra: Mapping[str, Any] | None,
    *,
    protected_keys: set[str],
) -> dict[str, Any]:
    merged = deepcopy(base)
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


def _workload_default_storage(workload_id: str) -> str:
    defaults = parser_workload_defaults(DEFAULT_PARSER_TYPE)
    workload = dict(defaults.get(workload_id) or {})
    storage = dict(workload.get("storage") or {})
    return str(storage.get("size") or "")


def default_spec() -> dict[str, Any]:
    parser_type = default_parser_type()
    canonical = {
        "enabled": True,
        "credentials": {
            "secretRef": "",
        },
        "parser": {
            "type": parser_type,
            "config": parser_config_defaults(parser_type),
            "secretRefs": parser_secret_ref_defaults(parser_type),
            "workloads": parser_workload_defaults(parser_type),
        },
    }
    return MirrorInstanceSpecModel.from_spec_dict(canonical).to_compat_spec_dict()


@dataclass
class MirrorInstanceSpecModel:
    raw_spec: dict[str, Any]
    enabled: bool
    credentials_secret_ref: str
    parser_type: str
    parser_config: dict[str, Any]
    parser_config_extras: dict[str, Any]
    parser_secret_refs: dict[str, str]
    parser_workloads: dict[str, dict[str, Any]]

    @property
    def source(self) -> dict[str, Any]:
        return {
            "steamAppId": int(self.parser_config.get("steamAppId") or 0),
            "owGameId": int(self.parser_config.get("owGameId") or 0),
            "language": str(self.parser_config.get("language") or "english").strip() or "english",
        }

    @property
    def sync(self) -> dict[str, Any]:
        sync_values = {
            key: deepcopy(value)
            for key, value in self.parser_config.items()
            if key in LEGACY_SYNC_FIELD_KEYS
        }
        return _merge_additive_unknown_keys(
            sync_values,
            self.parser_config_extras,
            protected_keys=set(sync_values),
        )

    @property
    def sync_extras(self) -> dict[str, Any]:
        return deepcopy(self.parser_config_extras)

    @property
    def legacy_parser_spec(self) -> dict[str, Any]:
        return {
            "proxyPoolSecretRef": str(
                self.parser_secret_refs.get("parserProxyPoolSecretRef") or ""
            ).strip()
        }

    @property
    def legacy_steamcmd_spec(self) -> dict[str, Any]:
        runner_workload = dict(self.parser_workloads.get("steamcmd") or {})
        runner_config = dict(runner_workload.get("config") or {})
        return {
            "proxy": {
                "type": str(runner_config.get("proxyType") or "socks5").strip() or "socks5",
                "secretRef": str(
                    self.parser_secret_refs.get("runnerProxySecretRef") or ""
                ).strip(),
            }
        }

    @property
    def legacy_storage_spec(self) -> dict[str, Any]:
        parser_workload = dict(self.parser_workloads.get("parser") or {})
        runner_workload = dict(self.parser_workloads.get("steamcmd") or {})
        return {
            "parser": deepcopy(parser_workload.get("storage") or {}),
            "runner": deepcopy(runner_workload.get("storage") or {}),
        }

    @classmethod
    def from_spec_dict(cls, spec: Mapping[str, Any] | None) -> "MirrorInstanceSpecModel":
        raw_spec = deepcopy(dict(spec or {}))
        enabled = bool(raw_spec.get("enabled", True))
        credentials_secret_ref = str(
            dict(raw_spec.get("credentials") or {}).get("secretRef") or ""
        ).strip()

        parser_block = dict(raw_spec.get("parser") or {})
        if any(key in parser_block for key in {"type", "config", "secretRefs", "workloads"}):
            parser_type = str(parser_block.get("type") or default_parser_type()).strip() or default_parser_type()
            contract = get_parser_contract(parser_type)
            raw_config = dict(parser_block.get("config") or {})
            raw_secret_refs = dict(parser_block.get("secretRefs") or {})
            raw_workloads = dict(parser_block.get("workloads") or {})
        else:
            parser_type = default_parser_type()
            contract = get_parser_contract(parser_type)
            source = dict(raw_spec.get("source") or {})
            sync = dict(raw_spec.get("sync") or {})
            raw_config = {
                "steamAppId": _parse_int(source.get("steamAppId"), 0),
                "owGameId": _parse_int(source.get("owGameId"), 0),
                "language": str(source.get("language") or "english").strip() or "english",
                **sync,
            }
            raw_secret_refs = {
                "parserProxyPoolSecretRef": str(
                    dict(raw_spec.get("parser") or {}).get("proxyPoolSecretRef") or ""
                ).strip(),
                "runnerProxySecretRef": str(
                    dict(dict(raw_spec.get("steamcmd") or {}).get("proxy") or {}).get("secretRef")
                    or ""
                ).strip(),
            }
            storage = dict(raw_spec.get("storage") or {})
            parser_storage = dict(storage.get("parser") or {})
            runner_storage = dict(storage.get("runner") or {})
            raw_workloads = {
                "parser": {
                    "storage": {
                        "size": str(
                            parser_storage.get("size") or _workload_default_storage("parser")
                        ).strip()
                        or _workload_default_storage("parser"),
                        "storageClassName": str(
                            parser_storage.get("storageClassName") or DEFAULT_STORAGE_CLASS
                        ).strip()
                        or DEFAULT_STORAGE_CLASS,
                    },
                    "config": {},
                },
                "steamcmd": {
                    "storage": {
                        "size": str(
                            runner_storage.get("size") or _workload_default_storage("steamcmd")
                        ).strip()
                        or _workload_default_storage("steamcmd"),
                        "storageClassName": str(
                            runner_storage.get("storageClassName") or DEFAULT_STORAGE_CLASS
                        ).strip()
                        or DEFAULT_STORAGE_CLASS,
                    },
                    "config": {
                        "proxyType": str(
                            dict(dict(raw_spec.get("steamcmd") or {}).get("proxy") or {}).get("type")
                            or "socks5"
                        ).strip()
                        or "socks5",
                    },
                },
            }

        defaults = parser_config_defaults(parser_type)
        merged_config = deep_merge(defaults, raw_config)
        parser_config = {
            field.key: field.normalize(merged_config.get(field.key))
            for field in contract.config_fields
        }
        parser_config_extras = {
            key: deepcopy(value)
            for key, value in merged_config.items()
            if key not in contract.config_fields_by_key
        }

        parser_secret_refs = parser_secret_ref_defaults(parser_type)
        for key in parser_secret_refs:
            parser_secret_refs[key] = str(raw_secret_refs.get(key) or "").strip()

        parser_workloads = parser_workload_defaults(parser_type)
        for workload in contract.workloads:
            rendered = dict(raw_workloads.get(workload.workload_id) or {})
            rendered_storage = dict(rendered.get("storage") or {})
            rendered_config = dict(rendered.get("config") or {})
            current = dict(parser_workloads.get(workload.workload_id) or {})
            current_storage = dict(current.get("storage") or {})
            current["storage"] = {
                "size": str(
                    rendered_storage.get("size") or current_storage.get("size") or workload.default_storage_size
                ).strip()
                or workload.default_storage_size,
                "storageClassName": str(
                    rendered_storage.get("storageClassName")
                    or current_storage.get("storageClassName")
                    or workload.default_storage_class
                ).strip()
                or workload.default_storage_class,
            }
            current_config = dict(current.get("config") or {})
            for field in workload.config_fields:
                current_config[field.key] = field.normalize(rendered_config.get(field.key))
            current["config"] = current_config
            parser_workloads[workload.workload_id] = current

        return cls(
            raw_spec=raw_spec,
            enabled=enabled,
            credentials_secret_ref=credentials_secret_ref,
            parser_type=parser_type,
            parser_config=parser_config,
            parser_config_extras=parser_config_extras,
            parser_secret_refs=parser_secret_refs,
            parser_workloads=parser_workloads,
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
        contract = get_parser_contract(self.parser_type)
        spec = _unknown_top_level_fields(self.raw_spec)
        spec["enabled"] = bool(self.enabled)
        spec["credentials"] = {
            "secretRef": self.credentials_secret_ref,
        }
        config = _merge_additive_unknown_keys(
            {
                field.key: deepcopy(self.parser_config[field.key])
                for field in contract.config_fields
            },
            self.parser_config_extras,
            protected_keys=set(contract.config_fields_by_key),
        )
        secret_refs = {
            key: str(value or "").strip()
            for key, value in self.parser_secret_refs.items()
        }
        workloads: dict[str, Any] = {}
        for workload in contract.workloads:
            rendered = dict(self.parser_workloads.get(workload.workload_id) or {})
            storage = dict(rendered.get("storage") or {})
            config_values = dict(rendered.get("config") or {})
            workloads[workload.workload_id] = {
                "storage": {
                    "size": str(storage.get("size") or workload.default_storage_size).strip()
                    or workload.default_storage_size,
                    "storageClassName": str(
                        storage.get("storageClassName") or workload.default_storage_class
                    ).strip()
                    or workload.default_storage_class,
                },
                "config": {
                    field.key: deepcopy(config_values.get(field.key, field.default))
                    for field in workload.config_fields
                },
            }
        spec["parser"] = {
            "type": self.parser_type,
            "config": config,
            "secretRefs": secret_refs,
            "workloads": workloads,
        }
        return spec

    def to_compat_spec_dict(self) -> dict[str, Any]:
        spec = self.to_spec_dict()
        spec["source"] = self.source
        spec["sync"] = self.sync
        spec["steamcmd"] = self.legacy_steamcmd_spec
        spec["storage"] = self.legacy_storage_spec
        parser_block = dict(spec.get("parser") or {})
        parser_block["proxyPoolSecretRef"] = self.legacy_parser_spec["proxyPoolSecretRef"]
        spec["parser"] = parser_block
        return spec


def normalize_instance_dict(instance: Mapping[str, Any] | None) -> dict[str, Any]:
    normalized = deepcopy(dict(instance or {}))
    normalized["spec"] = MirrorInstanceSpecModel.from_instance_dict(instance).to_compat_spec_dict()
    return normalized


def parser_config_form_values(parser_type: str, config: Mapping[str, Any] | None) -> dict[str, Any]:
    contract = get_parser_contract(parser_type)
    rendered_config = dict(config or {})
    values: dict[str, Any] = {}
    for field in contract.config_fields:
        if field.form_field is None:
            continue
        values[field.form_field] = field.normalize(rendered_config.get(field.key))
    return values


def validate_parser_config_form_inputs(parser_type: str, form: Mapping[str, Any]) -> dict[str, str]:
    contract = get_parser_contract(parser_type)
    errors: dict[str, str] = {}
    for field in contract.config_fields:
        if field.form_field is None:
            continue
        message = field.validate_form(form.get(field.form_field))
        if message:
            errors[field.form_field] = message
    return errors


def build_parser_config_from_form(
    parser_type: str,
    base_config: Mapping[str, Any] | None,
    form: Mapping[str, Any],
    raw_patch: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    contract = get_parser_contract(parser_type)
    current = dict(base_config or {})
    config = deep_merge(parser_config_defaults(parser_type), current)
    for field in contract.config_fields:
        if field.form_field is None:
            continue
        config[field.key] = field.parse_form(
            form.get(field.form_field),
            field.normalize(config.get(field.key)),
        )
    return _merge_additive_unknown_keys(
        config,
        raw_patch,
        protected_keys=set(contract.config_fields_by_key),
    )


def parser_config_form_minimum(parser_type: str, form_field: str) -> str:
    contract = get_parser_contract(parser_type)
    field = contract.config_fields_by_form.get(form_field)
    if field is None or field.minimum is None:
        return ""
    return str(field.minimum)


def iter_parser_config_env_items(parser_type: str, config: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    contract = get_parser_contract(parser_type)
    rendered = dict(config or {})
    return [
        (field.env_var, field.serialize_env(rendered.get(field.key)))
        for field in contract.config_fields
        if field.env_var
    ]


def load_parser_config_from_env(parser_type: str, environ: Mapping[str, str]) -> dict[str, Any]:
    contract = get_parser_contract(parser_type)
    values: dict[str, Any] = {}
    for field in contract.config_fields:
        if not field.env_var:
            continue
        values[field.config_attr] = field.normalize(environ.get(field.env_var))
    return values


def parser_overview_pairs(parser_type: str, config: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    contract = get_parser_contract(parser_type)
    rendered = dict(config or {})
    pairs: list[tuple[str, str]] = []
    for key in contract.overview_config_keys:
        field = contract.config_fields_by_key.get(key)
        if field is None:
            continue
        pairs.append((field.label, str(field.normalize(rendered.get(key)))))
    return pairs


def parser_subtitle_label(parser_type: str, config: Mapping[str, Any] | None) -> str:
    return parser_subtitle(parser_type, dict(config or {}))


SYNC_FIELD_SPECS: tuple[ParserConfigFieldSpec, ...] = tuple(
    field
    for field in get_parser_contract(DEFAULT_PARSER_TYPE).config_fields
    if field.key in LEGACY_SYNC_FIELD_KEYS
)
SYNC_FIELDS_BY_KEY = {field.key: field for field in SYNC_FIELD_SPECS}
SYNC_FIELDS_BY_FORM = {
    field.form_field: field for field in SYNC_FIELD_SPECS if field.form_field is not None
}


def sync_defaults() -> dict[str, Any]:
    return {
        field.key: deepcopy(field.default)
        for field in SYNC_FIELD_SPECS
    }


def sync_form_values(sync: Mapping[str, Any] | None) -> dict[str, Any]:
    rendered_sync = dict(sync or {})
    values: dict[str, Any] = {}
    for field in SYNC_FIELD_SPECS:
        if field.form_field is None:
            continue
        values[field.form_field] = field.normalize(rendered_sync.get(field.key))
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
        sync[field.key] = field.parse_form(
            form.get(field.form_field),
            field.normalize(sync.get(field.key)),
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
        (field.env_var, field.serialize_env(rendered_sync.get(field.key)))
        for field in SYNC_FIELD_SPECS
    ]


def load_sync_config_from_env(environ: Mapping[str, str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for field in SYNC_FIELD_SPECS:
        values[field.config_attr] = field.normalize(environ.get(field.env_var))
    return values


__all__ = [
    "DEFAULT_STORAGE_CLASS",
    "MirrorInstanceSpecModel",
    "build_parser_config_from_form",
    "build_sync_spec_from_form",
    "deep_merge",
    "default_spec",
    "default_parser_type",
    "get_parser_contract",
    "iter_parser_config_env_items",
    "iter_sync_env_items",
    "load_parser_config_from_env",
    "load_sync_config_from_env",
    "normalize_instance_dict",
    "parser_config_form_minimum",
    "parser_config_form_values",
    "parser_overview_pairs",
    "parser_subtitle_label",
    "parser_type_options",
    "sync_defaults",
    "sync_form_minimum",
    "sync_form_values",
    "validate_parser_config_form_inputs",
    "validate_sync_form_inputs",
]
