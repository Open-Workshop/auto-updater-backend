from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any

from kubernetes.client.rest import ApiException

from kube.kube_client import (
    delete_secret,
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
    build_workload_service,
    build_workload_statefulset,
)
from kube.mirror_instance import (
    common_labels,
    from_instance_dict,
    instance_name,
    normalize_instance,
    runner_config_secret_name,
    set_condition,
    workload_service_name,
)
from core.instance_schema import get_parser_contract


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


def _pod_main_image(pod: Any, container_name: str) -> str:
    if pod is None or getattr(pod, "spec", None) is None:
        return ""
    for container in list(getattr(pod.spec, "containers", None) or []):
        if str(getattr(container, "name", "") or "") == container_name:
            return str(getattr(container, "image", "") or "")
    return ""


def _condition_type_for_workload(label: str) -> str:
    return "".join(ch for ch in label.title() if ch.isalnum()) + "Ready"


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
        model = from_instance_dict(normalized)
        contract = get_parser_contract(model.parser_type)
        if not model.credentials_secret_ref:
            raise ValueError("spec.credentials.secretRef is required")

        # Validate referenced secrets before creating child workloads.
        read_secret_value(self.settings.namespace, model.credentials_secret_ref, "login")
        read_secret_value(self.settings.namespace, model.credentials_secret_ref, "password")
        secret_values: dict[str, str] = {}
        for secret_spec in contract.secret_specs:
            secret_ref = str(model.parser_secret_refs.get(secret_spec.key) or "").strip()
            if not secret_ref:
                continue
            secret_values[secret_spec.key] = (
                read_secret_value(
                    self.settings.namespace,
                    secret_ref,
                    secret_spec.secret_data_key,
                )
                or ""
            )
        runner_proxy_url = secret_values.get("runnerProxySecretRef", "")

        if runner_proxy_url:
            upsert_secret(
                self.settings.namespace,
                build_runner_config_secret(normalized, runner_proxy_url),
            )
        else:
            delete_secret(self.settings.namespace, runner_config_secret_name(name))

        for workload in contract.workloads:
            if workload.service_enabled:
                upsert_service(
                    self.settings.namespace,
                    build_workload_service(normalized, workload.workload_id),
                )
            upsert_statefulset(
                self.settings.namespace,
                build_workload_statefulset(
                    normalized,
                    workload.workload_id,
                    self.settings.app_image,
                    self.settings.singbox_image,
                    runner_proxy_url if workload.workload_id == "steamcmd" else "",
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
        model = from_instance_dict(instance)
        contract = get_parser_contract(model.parser_type)
        enabled = bool(model.enabled)
        generation = int(instance.get("metadata", {}).get("generation") or 0)
        workload_status: dict[str, Any] = {}
        workload_ready_map: dict[str, bool] = {}
        parser_pod_name = ""
        runner_pod_name = ""
        conditions = list((instance.get("status") or {}).get("conditions") or [])

        for workload in contract.workloads:
            pod = _component_pod(self.settings.namespace, name, workload.component)
            ready = _pod_ready(pod)
            pod_name = str(getattr(getattr(pod, "metadata", None), "name", "") or "")
            workload_ready_map[workload.workload_id] = ready
            workload_status[workload.workload_id] = {
                "podName": pod_name,
                "state": str(getattr(getattr(pod, "status", None), "phase", "") or "Missing"),
                "ready": ready,
                "image": _pod_main_image(pod, workload.main_container_name),
                "serviceName": workload_service_name(name, model.parser_type, workload.workload_id),
                "observedGeneration": generation,
            }
            if workload.workload_id == "parser":
                parser_pod_name = pod_name
            if workload.workload_id == "steamcmd":
                runner_pod_name = pod_name
            condition_type = _condition_type_for_workload(workload.display_label)
            conditions = set_condition(
                conditions,
                condition_type,
                ready,
                condition_type if ready else condition_type.replace("Ready", "NotReady"),
                pod_name or f"{workload.display_label.lower()} pod not created yet",
            )

        all_ready = all(workload_ready_map.values()) if workload_ready_map else False
        phase = "Paused"
        if enabled:
            phase = "Ready" if all_ready else "Progressing"
        conditions = set_condition(
            conditions,
            "Ready",
            all_ready and enabled,
            phase,
            phase,
        )
        if "parser" in workload_ready_map:
            conditions = set_condition(
                conditions,
                "ParserReady",
                workload_ready_map["parser"],
                "ParserReady" if workload_ready_map["parser"] else "ParserNotReady",
                parser_pod_name or "parser pod not created yet",
            )
        if "steamcmd" in workload_ready_map:
            conditions = set_condition(
                conditions,
                "RunnerReady",
                workload_ready_map["steamcmd"],
                "RunnerReady" if workload_ready_map["steamcmd"] else "RunnerNotReady",
                runner_pod_name or "runner pod not created yet",
            )
        merge_instance_status(
            self.settings.namespace,
            name,
            {
                "phase": phase,
                "parserType": model.parser_type,
                "workloads": workload_status,
                "parserPod": parser_pod_name,
                "runnerPod": runner_pod_name,
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
