#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.http_utils import parse_proxy_url
from core.instance_migration import (
    instance_needs_migration,
    instance_requires_runtime_recovery,
    migrated_instance_manifest,
)
from core.parser_registry import (
    default_parser_type,
    get_parser_contract,
    parser_config_defaults,
    parser_secret_ref_defaults,
    parser_workload_defaults,
)
from kube.mirror_instance import managed_runner_proxy_secret_name


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Migrate MirrorInstance resources to the canonical parser.* schema.",
    )
    parser.add_argument(
        "--namespace",
        default="auto-updater",
        help="Kubernetes namespace containing MirrorInstance resources.",
    )
    parser.add_argument(
        "--kube-cli",
        default="kubectl",
        help='kubectl command to use, for example: "k3s kubectl".',
    )
    parser.add_argument(
        "--name",
        default="",
        help="Optional single MirrorInstance name to migrate.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the names that would be migrated without updating resources.",
    )
    return parser.parse_args()


def _run(command: list[str], *, input_text: str | None = None) -> str:
    completed = subprocess.run(
        command,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr.strip()}"
        )
    return completed.stdout


def _load_instances(kube_cli: list[str], namespace: str, name: str) -> list[dict[str, Any]]:
    if name:
        output = _run(
            [
                *kube_cli,
                "-n",
                namespace,
                "get",
                "mirrorinstance",
                name,
                "-o",
                "json",
            ]
        )
        return [json.loads(output)]
    output = _run(
        [
            *kube_cli,
            "-n",
            namespace,
            "get",
            "mirrorinstances",
            "-o",
            "json",
        ]
    )
    payload = json.loads(output)
    return list(payload.get("items") or [])


def _get_json(command: list[str]) -> dict[str, Any]:
    return json.loads(_run(command))


def _try_get_json(command: list[str]) -> dict[str, Any] | None:
    try:
        return _get_json(command)
    except RuntimeError as exc:
        if "NotFound" in str(exc):
            return None
        raise


def _replace_instance(kube_cli: list[str], manifest: dict[str, Any]) -> None:
    _run(
        [*kube_cli, "replace", "-f", "-"],
        input_text=json.dumps(manifest),
    )


def _env_value(env_items: list[dict[str, Any]], name: str) -> str | None:
    for item in env_items:
        if str(item.get("name") or "") != name:
            continue
        if "value" not in item:
            return None
        value = item.get("value")
        if value is None:
            return None
        return str(value)
    return None


def _env_secret_name(env_items: list[dict[str, Any]], name: str) -> str:
    for item in env_items:
        if str(item.get("name") or "") != name:
            continue
        secret_ref = dict(dict(item.get("valueFrom") or {}).get("secretKeyRef") or {})
        return str(secret_ref.get("name") or "").strip()
    return ""


def _statefulset_name(instance_name: str, workload_id: str) -> str:
    suffix = "parser" if workload_id == "parser" else "steamcmd"
    return f"{instance_name}-{suffix}"


def _load_statefulset(kube_cli: list[str], namespace: str, name: str) -> dict[str, Any] | None:
    return _try_get_json(
        [
            *kube_cli,
            "-n",
            namespace,
            "get",
            "statefulset",
            name,
            "-o",
            "json",
        ]
    )


def _statefulset_storage(statefulset: dict[str, Any] | None) -> tuple[str, str]:
    templates = list(dict(statefulset or {}).get("spec", {}).get("volumeClaimTemplates") or [])
    if not templates:
        return "", ""
    claim = dict(templates[0].get("spec") or {})
    resources = dict(claim.get("resources") or {})
    requests = dict(resources.get("requests") or {})
    return (
        str(requests.get("storage") or "").strip(),
        str(claim.get("storageClassName") or "").strip(),
    )


def _load_secret_data(kube_cli: list[str], namespace: str, name: str) -> dict[str, str]:
    secret = _try_get_json(
        [
            *kube_cli,
            "-n",
            namespace,
            "get",
            "secret",
            name,
            "-o",
            "json",
        ]
    )
    if secret is None:
        return {}
    decoded: dict[str, str] = {}
    for key, value in dict(secret.get("data") or {}).items():
        decoded[key] = base64.b64decode(value).decode("utf-8")
    return decoded


def _controller_revision_env_snapshots(
    kube_cli: list[str],
    namespace: str,
    statefulset_name: str,
) -> list[list[dict[str, Any]]]:
    payload = _get_json(
        [
            *kube_cli,
            "-n",
            namespace,
            "get",
            "controllerrevisions",
            "-o",
            "json",
        ]
    )
    matching = [
        item
        for item in list(payload.get("items") or [])
        if str(dict(item.get("metadata") or {}).get("name") or "").startswith(f"{statefulset_name}-")
    ]
    matching.sort(key=lambda item: int(item.get("revision") or 0), reverse=True)
    snapshots: list[list[dict[str, Any]]] = []
    for item in matching:
        template = dict(dict(item.get("data") or {}).get("spec") or {}).get("template") or {}
        spec = dict(template.get("spec") or {})
        containers = list(spec.get("containers") or [])
        if not containers:
            continue
        env_items = list(dict(containers[0]).get("env") or [])
        if env_items:
            snapshots.append(env_items)
    current = _load_statefulset(kube_cli, namespace, statefulset_name)
    current_containers = list(dict(dict(current or {}).get("spec", {}).get("template", {}).get("spec") or {}).get("containers") or [])
    if current_containers:
        env_items = list(dict(current_containers[0]).get("env") or [])
        if env_items:
            snapshots.append(env_items)
    return snapshots


def _best_parser_env_snapshot(
    kube_cli: list[str],
    namespace: str,
    instance_name: str,
) -> list[dict[str, Any]]:
    snapshots = _controller_revision_env_snapshots(
        kube_cli,
        namespace,
        _statefulset_name(instance_name, "parser"),
    )
    fallback: list[dict[str, Any]] = []
    for snapshot in snapshots:
        steam_app_id = int(_env_value(snapshot, "OW_STEAM_APP_ID") or "0")
        if steam_app_id > 1:
            return snapshot
        if not fallback:
            fallback = snapshot
    return fallback


def _runtime_recovered_manifest(
    kube_cli: list[str],
    namespace: str,
    instance: dict[str, Any],
) -> dict[str, Any]:
    metadata = dict(instance.get("metadata") or {})
    name = str(metadata.get("name") or "").strip()
    if not name:
        raise RuntimeError("instance name is required for runtime recovery")

    env_items = _best_parser_env_snapshot(kube_cli, namespace, name)
    if not env_items:
        raise RuntimeError(f"no parser runtime snapshot found for {name}")

    parser_type = _env_value(env_items, "OW_PARSER_TYPE") or default_parser_type()
    contract = get_parser_contract(parser_type)
    parser_config = parser_config_defaults(parser_type)
    for field in contract.config_fields:
        if not field.env_var:
            continue
        raw_value = _env_value(env_items, field.env_var)
        if raw_value is None:
            continue
        parser_config[field.key] = field.normalize(raw_value)
    steam_app_id = int(parser_config.get("steamAppId") or 0)
    if steam_app_id <= 1:
        raise RuntimeError(f"failed to recover a valid Steam App ID for {name}")

    parser_secret_refs = parser_secret_ref_defaults(parser_type)
    parser_proxy_secret_ref = _env_secret_name(env_items, "OW_STEAM_PROXY_POOL")
    if parser_proxy_secret_ref:
        parser_secret_refs["parserProxyPoolSecretRef"] = parser_proxy_secret_ref

    runner_proxy_secret_ref = managed_runner_proxy_secret_name(name)
    runner_proxy_data = _load_secret_data(kube_cli, namespace, runner_proxy_secret_ref)
    runner_proxy_url = str(runner_proxy_data.get("proxyUrl") or "").strip()
    runner_proxy_type = "socks5"
    if runner_proxy_url:
        runner_proxy_type = "socks5" if parse_proxy_url(runner_proxy_url).is_socks else "http"
        parser_secret_refs["runnerProxySecretRef"] = runner_proxy_secret_ref

    parser_workloads = parser_workload_defaults(parser_type)
    parser_storage_size, parser_storage_class = _statefulset_storage(
        _load_statefulset(kube_cli, namespace, _statefulset_name(name, "parser"))
    )
    runner_storage_size, runner_storage_class = _statefulset_storage(
        _load_statefulset(kube_cli, namespace, _statefulset_name(name, "steamcmd"))
    )
    if parser_storage_size:
        parser_workloads["parser"]["storage"]["size"] = parser_storage_size
    if parser_storage_class:
        parser_workloads["parser"]["storage"]["storageClassName"] = parser_storage_class
    if runner_storage_size:
        parser_workloads["steamcmd"]["storage"]["size"] = runner_storage_size
    if runner_storage_class:
        parser_workloads["steamcmd"]["storage"]["storageClassName"] = runner_storage_class
    parser_workloads["steamcmd"]["config"]["proxyType"] = runner_proxy_type

    credentials_secret_ref = str(dict(dict(instance.get("spec") or {}).get("credentials") or {}).get("secretRef") or "").strip()
    if not credentials_secret_ref:
        credentials_secret_ref = _env_secret_name(env_items, "OW_LOGIN")
    if not credentials_secret_ref:
        raise RuntimeError(f"failed to recover credentials secretRef for {name}")

    recovered = dict(instance)
    recovered["spec"] = {
        "enabled": bool(dict(instance.get("spec") or {}).get("enabled", True)),
        "credentials": {
            "secretRef": credentials_secret_ref,
        },
        "parser": {
            "type": parser_type,
            "config": parser_config,
            "secretRefs": parser_secret_refs,
            "workloads": parser_workloads,
        },
    }
    return migrated_instance_manifest(recovered)


def main() -> int:
    args = _parse_args()
    kube_cli = shlex.split(args.kube_cli)
    if not kube_cli:
        raise SystemExit("--kube-cli must not be empty")

    instances = _load_instances(kube_cli, args.namespace, args.name)
    if not instances:
        print("No MirrorInstance resources found.")
        return 0

    migrated = 0
    failures: list[str] = []
    for instance in instances:
        name = str(dict(instance.get("metadata") or {}).get("name") or "<unnamed>")
        try:
            if not instance_needs_migration(instance):
                print(f"Skipping {name}: already canonical")
                continue
            migrated += 1
            if instance_requires_runtime_recovery(instance):
                manifest = _runtime_recovered_manifest(kube_cli, args.namespace, instance)
                action = "recover and migrate"
            else:
                manifest = migrated_instance_manifest(instance)
                action = "migrate"
            if args.dry_run:
                print(f"Would {action} {name}")
                continue
            _replace_instance(kube_cli, manifest)
            print(f"Migrated {name}")
        except Exception as exc:
            failures.append(f"{name}: {exc}")
            print(f"Failed to migrate {name}: {exc}", file=sys.stderr)

    if args.dry_run:
        print(f"Dry run complete: {migrated} resource(s) need migration.")
    else:
        print(f"Migration complete: {migrated} resource(s) updated.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
