from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from core.instance_schema import MirrorInstanceSpecModel


_REMOVED_METADATA_FIELDS = {
    "creationTimestamp",
    "generation",
    "managedFields",
    "selfLink",
    "uid",
}


def canonical_instance_spec(instance: Mapping[str, Any] | None) -> dict[str, Any]:
    return MirrorInstanceSpecModel.from_instance_dict(instance).to_spec_dict()


def instance_needs_migration(instance: Mapping[str, Any] | None) -> bool:
    if not isinstance(instance, Mapping):
        return False
    current_spec = dict(instance.get("spec") or {})
    return current_spec != canonical_instance_spec(instance)


def instance_requires_runtime_recovery(instance: Mapping[str, Any] | None) -> bool:
    if not isinstance(instance, Mapping):
        return False
    spec = dict(instance.get("spec") or {})
    parser = dict(spec.get("parser") or {})
    has_new_shape = any(key in parser for key in {"type", "config", "secretRefs", "workloads"})
    has_legacy_shape = any(key in spec for key in {"source", "sync", "steamcmd", "storage"}) or bool(
        parser.get("proxyPoolSecretRef")
    )
    return not has_new_shape and not has_legacy_shape


def migrated_instance_manifest(instance: Mapping[str, Any]) -> dict[str, Any]:
    payload = deepcopy(dict(instance or {}))
    payload["spec"] = canonical_instance_spec(instance)
    payload.pop("status", None)
    metadata = dict(payload.get("metadata") or {})
    for field_name in _REMOVED_METADATA_FIELDS:
        metadata.pop(field_name, None)
    payload["metadata"] = metadata
    return payload


__all__ = [
    "canonical_instance_spec",
    "instance_needs_migration",
    "instance_requires_runtime_recovery",
    "migrated_instance_manifest",
]
