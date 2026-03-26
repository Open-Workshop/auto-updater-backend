from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from kubernetes.client.rest import ApiException

from kube.kube_client import (
    get_kube_clients,
    list_instances,
    merge_instance_status,
    read_secret_value,
    upsert_secret,
    upsert_service,
    upsert_statefulset,
)
from kube.kube_resources import (
    build_parser_service,
    build_parser_statefulset,
    build_runner_config_secret,
    build_runner_service,
    build_runner_statefulset,
)
from kube.mirror_instance import common_labels, instance_name, normalize_instance, set_condition


@dataclass
class OperatorSettings:
    namespace: str
    interval_seconds: int
    app_image: str
    singbox_image: str


def load_operator_settings() -> OperatorSettings:
    try:
        interval = int(os.environ.get("AUTO_UPDATER_RECONCILE_INTERVAL", "15"))
    except ValueError:
        interval = 15
    return OperatorSettings(
        namespace=os.environ.get("AUTO_UPDATER_NAMESPACE", "auto-updater").strip() or "auto-updater",
        interval_seconds=max(5, interval),
        app_image=os.environ.get("AUTO_UPDATER_IMAGE", "ow-mirror:latest").strip() or "ow-mirror:latest",
        singbox_image=os.environ.get("AUTO_UPDATER_SINGBOX_IMAGE", "ghcr.io/sagernet/sing-box:latest").strip()
        or "ghcr.io/sagernet/sing-box:latest",
    )


def _selector(labels: dict[str, str]) -> str:
    return ",".join(f"{key}={value}" for key, value in labels.items())


def _pod_ready(pod: Any) -> bool:
    if pod is None or pod.status is None:
        return False
    if pod.status.phase != "Running":
        return False
    for condition in pod.status.conditions or []:
        if condition.type == "Ready":
            return condition.status == "True"
    return False


def _component_pod(namespace: str, name: str, component: str) -> Any | None:
    labels = common_labels(name, component)
    pods = get_kube_clients().core.list_namespaced_pod(
        namespace,
        label_selector=_selector(labels),
    ).items
    if not pods:
        return None
    pods.sort(
        key=lambda item: (item.metadata.creation_timestamp.isoformat() if item.metadata.creation_timestamp else ""),
        reverse=True,
    )
    return pods[0]


class MirrorInstanceOperator:
    def __init__(self, settings: OperatorSettings) -> None:
        self.settings = settings

    def run_forever(self) -> None:
        logging.info(
            "Starting operator in namespace=%s, reconcile interval=%ss",
            self.settings.namespace,
            self.settings.interval_seconds,
        )
        while True:
            self.reconcile_all()
            time.sleep(self.settings.interval_seconds)

    def reconcile_all(self) -> None:
        instances = list_instances(self.settings.namespace)
        for instance in instances:
            try:
                self.reconcile_instance(instance)
            except Exception as exc:
                logging.exception(
                    "Failed to reconcile MirrorInstance %s",
                    instance.get("metadata", {}).get("name", "-"),
                )
                self._mark_reconcile_error(instance, exc)

    def reconcile_instance(self, instance: dict[str, Any]) -> None:
        normalized = normalize_instance(instance)
        name = instance_name(normalized)
        spec = normalized["spec"]
        credentials_secret = str(spec["credentials"].get("secretRef") or "").strip()
        if not credentials_secret:
            raise ValueError("spec.credentials.secretRef is required")
        runner_proxy_secret = str(spec["steamcmd"]["proxy"].get("secretRef") or "").strip()
        if not runner_proxy_secret:
            raise ValueError("spec.steamcmd.proxy.secretRef is required")

        # Validate referenced secrets before creating child workloads.
        read_secret_value(self.settings.namespace, credentials_secret, "login")
        read_secret_value(self.settings.namespace, credentials_secret, "password")
        parser_proxy_secret = str(spec["parser"].get("proxyPoolSecretRef") or "").strip()
        if parser_proxy_secret:
            read_secret_value(self.settings.namespace, parser_proxy_secret, "proxyPool")
        runner_proxy_url = read_secret_value(self.settings.namespace, runner_proxy_secret, "proxyUrl")

        upsert_secret(
            self.settings.namespace,
            build_runner_config_secret(normalized, runner_proxy_url),
        )
        upsert_service(self.settings.namespace, build_parser_service(normalized))
        upsert_service(self.settings.namespace, build_runner_service(normalized))
        upsert_statefulset(
            self.settings.namespace,
            build_parser_statefulset(normalized, self.settings.app_image),
        )
        upsert_statefulset(
            self.settings.namespace,
            build_runner_statefulset(
                normalized,
                self.settings.app_image,
                self.settings.singbox_image,
            ),
        )
        self._sync_status(normalized)

    def _mark_reconcile_error(self, instance: dict[str, Any], exc: Exception) -> None:
        name = instance_name(instance)
        message = str(exc) or exc.__class__.__name__
        conditions = list((instance.get("status") or {}).get("conditions") or [])
        conditions = set_condition(
            conditions,
            "Ready",
            False,
            "Error",
            message,
        )
        try:
            merge_instance_status(
                self.settings.namespace,
                name,
                {
                    "phase": "Error",
                    "lastError": message,
                    "conditions": conditions,
                },
            )
        except Exception:
            logging.exception("Failed to write error status for %s", name)

    def _sync_status(self, instance: dict[str, Any]) -> None:
        name = instance_name(instance)
        enabled = bool(instance["spec"].get("enabled", True))
        parser_pod = _component_pod(self.settings.namespace, name, "parser")
        runner_pod = _component_pod(self.settings.namespace, name, "runner")
        parser_ready = _pod_ready(parser_pod)
        runner_ready = _pod_ready(runner_pod)
        phase = "Paused"
        if enabled:
            phase = "Ready" if (parser_ready and runner_ready) else "Progressing"
        conditions = list((instance.get("status") or {}).get("conditions") or [])
        conditions = set_condition(
            conditions,
            "ParserReady",
            parser_ready,
            "ParserReady" if parser_ready else "ParserNotReady",
            parser_pod.metadata.name if parser_pod else "parser pod not created yet",
        )
        conditions = set_condition(
            conditions,
            "RunnerReady",
            runner_ready,
            "RunnerReady" if runner_ready else "RunnerNotReady",
            runner_pod.metadata.name if runner_pod else "runner pod not created yet",
        )
        conditions = set_condition(
            conditions,
            "Ready",
            parser_ready and runner_ready and enabled,
            phase,
            phase,
        )
        merge_instance_status(
            self.settings.namespace,
            name,
            {
                "phase": phase,
                "parserPod": parser_pod.metadata.name if parser_pod else "",
                "runnerPod": runner_pod.metadata.name if runner_pod else "",
                "conditions": conditions,
            },
        )


def run_operator() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler()],
    )
    try:
        get_kube_clients()
    except Exception:
        logging.exception("Failed to initialize kubernetes client")
        return 2
    operator = MirrorInstanceOperator(load_operator_settings())
    try:
        operator.run_forever()
    except ApiException:
        logging.exception("Kubernetes API failure in reconcile loop")
        return 1
    except KeyboardInterrupt:
        return 0
    return 0
