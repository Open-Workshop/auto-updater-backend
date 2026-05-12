from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional

import requests

from core.telemetry import start_span
from ow.ow_api import ApiClient
from sync.metadata import OW_LOG
from sync.state import SourceDependency, SourceTagGroup


class TagManager:
    def __init__(
        self,
        api: ApiClient,
        game_id: int,
        page_size: int,
        *,
        enabled: bool,
        prune: bool,
        name_to_id: Dict[str, int] | None = None,
        id_to_name: Dict[int, str] | None = None,
        group_name_to_id: Dict[str, int] | None = None,
        tag_id_to_group_id: Dict[int, int | None] | None = None,
        lock: threading.Lock | None = None,
    ) -> None:
        self.api = api
        self.game_id = game_id
        self.page_size = page_size
        self.enabled = enabled
        self.prune = prune
        self._name_to_id = name_to_id if name_to_id is not None else {}
        self._id_to_name = id_to_name if id_to_name is not None else {}
        self._group_name_to_id = group_name_to_id if group_name_to_id is not None else {}
        self._tag_id_to_group_id = (
            tag_id_to_group_id if tag_id_to_group_id is not None else {}
        )
        self._lock = lock or threading.Lock()

    def clone(self, api: ApiClient) -> "TagManager":
        return TagManager(
            api,
            self.game_id,
            self.page_size,
            enabled=self.enabled,
            prune=self.prune,
            name_to_id=self._name_to_id,
            id_to_name=self._id_to_name,
            group_name_to_id=self._group_name_to_id,
            tag_id_to_group_id=self._tag_id_to_group_id,
            lock=self._lock,
        )

    def preload(self) -> None:
        if not self.enabled:
            return
        with start_span(
            "tags.preload",
            {
                "ow.game_id": self.game_id,
                "tags.page_size": self.page_size,
            },
        ):
            for group in self.api.list_tag_groups(self.game_id, self.page_size):
                group_name = group.get("name") or group.get("group_name")
                group_id = group.get("id") or group.get("group_id")
                if group_name and group_id is not None:
                    with self._lock:
                        self._group_name_to_id[self._normalize_key(str(group_name))] = int(group_id)
            for tag in self.api.list_tags(self.game_id, self.page_size, include=["group"]):
                name = tag.get("name") or tag.get("tag_name")
                tag_id = tag.get("id") or tag.get("tag_id")
                tag_group_id: int | None = None
                group = tag.get("group")
                if isinstance(group, dict):
                    group_name = group.get("name") or group.get("group_name")
                    group_id = group.get("id") or group.get("group_id")
                    if group_name and group_id is not None:
                        with self._lock:
                            self._group_name_to_id[self._normalize_key(str(group_name))] = int(group_id)
                    if group_id is not None:
                        tag_group_id = int(group_id)
                if name and tag_id:
                    with self._lock:
                        # Match by normalized tag name and cache group metadata separately,
                        # so grouped sources can reuse the same tag ids without duplication.
                        self._name_to_id[self._normalize_key(str(name))] = int(tag_id)
                        self._id_to_name[int(tag_id)] = str(name)
                        self._tag_id_to_group_id[int(tag_id)] = tag_group_id

    def sync_mod_tags(
        self,
        ow_mod_id: int,
        tag_names: List[str],
        tag_groups: List[SourceTagGroup] | None = None,
    ) -> None:
        if not self.enabled:
            return
        tag_names = self._unique_tag_names(tag_names)
        normalized_groups = self._normalize_tag_groups(tag_groups)
        grouped_tag_names = self._unique_tag_names(
            tag_name
            for tag_group in normalized_groups
            for tag_name in tag_group.tags
        )
        grouped_tag_name_set = {name.lower() for name in grouped_tag_names}
        tag_names = [name for name in tag_names if name.lower() not in grouped_tag_name_set]
        with start_span(
            "tags.sync",
            {
                "ow.mod_id": ow_mod_id,
                "tags.desired": len(tag_names) + len(grouped_tag_names),
                "tags.groups": len(normalized_groups),
                "tags.grouped": len(grouped_tag_names),
                "tags.prune": self.prune,
            },
        ):
            desired_tag_ids = self._resolve_grouped_tag_ids(normalized_groups)
            desired_tag_ids.extend(self._resolve_tag_ids(tag_names, group_id=None))
            unique_desired_tag_ids: List[int] = []
            seen_tag_ids: set[int] = set()
            for tag_id in desired_tag_ids:
                if tag_id in seen_tag_ids:
                    continue
                seen_tag_ids.add(tag_id)
                unique_desired_tag_ids.append(tag_id)
            desired_tag_ids = unique_desired_tag_ids
            current_tag_ids = self.api.get_mod_tags(ow_mod_id)
            desired_tag_id_set = set(desired_tag_ids)
            current_tag_id_set = set(current_tag_ids)
            missing_tags = [tid for tid in desired_tag_ids if tid not in current_tag_id_set]
            extra_tags = [tid for tid in current_tag_ids if tid not in desired_tag_id_set]
            if missing_tags or extra_tags:
                with self._lock:
                    id_to_name = dict(self._id_to_name)
                OW_LOG.debug(
                    "OW mod %s tags: current=%s desired=%s add=%s prune=%s",
                    ow_mod_id,
                    len(current_tag_ids),
                    len(desired_tag_ids),
                    [id_to_name.get(tid, tid) for tid in missing_tags],
                    [id_to_name.get(tid, tid) for tid in extra_tags],
                )
            for tag_id in desired_tag_ids:
                if tag_id not in current_tag_id_set:
                    self.api.add_mod_tag(ow_mod_id, tag_id)
                    current_tag_id_set.add(tag_id)
            if self.prune:
                for tag_id in current_tag_ids:
                    if tag_id not in desired_tag_id_set:
                        self.api.delete_mod_tag(ow_mod_id, tag_id)

    def _resolve_grouped_tag_ids(self, tag_groups: List[SourceTagGroup]) -> List[int]:
        desired_tag_ids: List[int] = []
        for tag_group in tag_groups:
            group_id = self._resolve_group_id(tag_group.name)
            if group_id is None:
                continue
            desired_tag_ids.extend(self._resolve_tag_ids(tag_group.tags, group_id=group_id))
        return desired_tag_ids

    def _resolve_group_id(self, group_name: str) -> int | None:
        key = self._normalize_key(group_name)
        if not key:
            return None
        with self._lock:
            group_id = self._group_name_to_id.get(key)
            if group_id is not None:
                return group_id
            try:
                group_id = self.api.add_tag_group(group_name)
            except (requests.RequestException, RuntimeError) as exc:
                OW_LOG.warning("Failed to add tag group %s: %s", group_name, exc)
                return None
            self._group_name_to_id[key] = group_id
            return group_id

    def _resolve_tag_ids(self, tag_names: List[str], *, group_id: int | None) -> List[int]:
        desired_tag_ids: List[int] = []
        for tag_name in tag_names:
            key = self._normalize_key(tag_name)
            if not key:
                continue
            with self._lock:
                tag_id = self._name_to_id.get(key)
                current_group_id = self._tag_id_to_group_id.get(tag_id) if tag_id else None
                if not tag_id:
                    try:
                        tag_id = self.api.add_tag(tag_name, group_id=group_id)
                    except (requests.RequestException, RuntimeError) as exc:
                        OW_LOG.warning("Failed to add tag %s: %s", tag_name, exc)
                        continue
                    self.api.associate_game_tag(self.game_id, tag_id)
                    self._name_to_id[key] = tag_id
                    self._id_to_name[tag_id] = tag_name
                    self._tag_id_to_group_id[tag_id] = group_id
                elif group_id is not None and current_group_id != group_id:
                    try:
                        self.api.patch_tag(tag_id, group_id=group_id)
                    except (requests.RequestException, RuntimeError) as exc:
                        OW_LOG.warning(
                            "Failed to update tag %s group to %s: %s",
                            tag_name,
                            group_id,
                            exc,
                        )
                    else:
                        self._tag_id_to_group_id[tag_id] = group_id
            desired_tag_ids.append(tag_id)
        return desired_tag_ids

    @staticmethod
    def _unique_tag_names(tag_names: List[str]) -> List[str]:
        unique_tag_names: List[str] = []
        seen: set[str] = set()
        for tag_name in tag_names:
            rendered = str(tag_name or "").strip()
            if not rendered:
                continue
            key = rendered.lower()
            if key in seen:
                continue
            seen.add(key)
            unique_tag_names.append(rendered)
        return unique_tag_names

    @staticmethod
    def _normalize_key(value: str) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _normalize_tag_groups(
        tag_groups: List[SourceTagGroup] | None,
    ) -> List[SourceTagGroup]:
        normalized_groups: List[SourceTagGroup] = []
        for group in tag_groups or []:
            if isinstance(group, SourceTagGroup):
                normalized = group
            elif isinstance(group, dict):
                normalized = SourceTagGroup(
                    str(group.get("name") or group.get("group_name") or "").strip(),
                    list(group.get("tags") or group.get("items") or []),
                )
            else:
                normalized = SourceTagGroup(
                    str(getattr(group, "name", "") or "").strip(),
                    list(getattr(group, "tags", []) or []),
                )
            if not normalized.name or not normalized.tags:
                continue
            normalized_groups.append(normalized)
        return normalized_groups


class DependencyManager:
    def __init__(
        self,
        api: ApiClient,
        *,
        enabled: bool,
        prune: bool,
        scrape_required_items: bool,
        enqueue_metadata: Callable[[str], None],
        lookup_mod: Callable[[str], Optional[Dict[str, Any]]],
        pending_dependency_links: Dict[int, Dict[str, Any]] | None = None,
        lock: threading.Lock | None = None,
    ) -> None:
        self.api = api
        self.enabled = enabled
        self.prune = prune
        self.scrape_required_items = scrape_required_items
        self.enqueue_metadata = enqueue_metadata
        self.lookup_mod = lookup_mod
        self.pending_dependency_links = (
            pending_dependency_links if pending_dependency_links is not None else {}
        )
        self._lock = lock or threading.Lock()

    def clone(self, api: ApiClient) -> "DependencyManager":
        return DependencyManager(
            api,
            enabled=self.enabled,
            prune=self.prune,
            scrape_required_items=self.scrape_required_items,
            enqueue_metadata=self.enqueue_metadata,
            lookup_mod=self.lookup_mod,
            pending_dependency_links=self.pending_dependency_links,
            lock=self._lock,
        )

    def queue_missing_sources(self, dep_source_ids: List[str]) -> None:
        if not self.enabled or not self.scrape_required_items:
            return
        for dep_source_id in dep_source_ids:
            self.enqueue_metadata(str(dep_source_id))

    @staticmethod
    def _normalize_dependency_items(dep_items: List[SourceDependency] | List[Any]) -> List[SourceDependency]:
        normalized: List[SourceDependency] = []
        for item in dep_items or []:
            source_id = str(getattr(item, "source_id", item) or "").strip()
            if not source_id:
                continue
            normalized.append(
                SourceDependency(
                    source_id,
                    bool(getattr(item, "optional", False)),
                )
            )
        return normalized

    def _current_dependency_map(self, ow_mod_id: int) -> Dict[int, bool]:
        current_dep_map: Dict[int, bool] = {}
        for dep_id, optional in self.api.get_mod_dependency_links(ow_mod_id):
            current_dep_map[int(dep_id)] = bool(optional)
        return current_dep_map

    def sync_dependencies(
        self,
        ow_mod_id: int,
        dep_items: List[SourceDependency],
        deps_ok: bool,
    ) -> None:
        if not self.enabled or not self.scrape_required_items:
            return
        dep_items = self._normalize_dependency_items(dep_items)
        with start_span(
            "dependencies.sync",
            {
                "ow.mod_id": ow_mod_id,
                "deps.desired_sources": len(dep_items),
                "deps.prune": self.prune,
                "deps.ok": deps_ok,
            },
        ):
            desired_dep_ids: Dict[int, bool] = {}
            missing_sources: List[str] = []
            for dep_item in dep_items:
                dep_source_id = dep_item.source_id
                dep_mod = self.lookup_mod(dep_source_id)
                if dep_mod:
                    desired_dep_ids[int(dep_mod.get("id"))] = dep_item.optional
                else:
                    missing_sources.append(dep_source_id)
                    self.enqueue_metadata(dep_source_id)

            current_dep_map = self._current_dependency_map(ow_mod_id)
            for dep_id, optional in desired_dep_ids.items():
                if current_dep_map.get(dep_id) != optional:
                    self.api.upsert_mod_dependency(ow_mod_id, dep_id, optional=optional)

            allow_prune = self.prune and deps_ok and not missing_sources
            if allow_prune:
                for dep_id in current_dep_map:
                    if dep_id not in desired_dep_ids:
                        self.api.delete_mod_dependency(ow_mod_id, dep_id)
            elif self.prune and not deps_ok:
                OW_LOG.debug(
                    "Skip dependency prune for %s due to Steam scrape failure",
                    ow_mod_id,
                )

            if missing_sources:
                with self._lock:
                    self.pending_dependency_links[ow_mod_id] = {
                        "deps": dep_items,
                        "deps_ok": deps_ok,
                    }
            else:
                with self._lock:
                    self.pending_dependency_links.pop(ow_mod_id, None)

    def retry_pending(self) -> None:
        with self._lock:
            pending_items = list(self.pending_dependency_links.items())
        if not pending_items:
            return
        with start_span(
            "dependencies.retry_pending",
            {"deps.pending_mods": len(pending_items)},
        ):
            for ow_mod_id, info in pending_items:
                dep_items = self._normalize_dependency_items(info.get("deps", []))
                deps_ok = bool(info.get("deps_ok", True))
                desired_dep_ids: Dict[int, bool] = {}
                missing_sources: List[str] = []
                for dep_item in dep_items:
                    dep_mod = self.lookup_mod(dep_item.source_id)
                    if dep_mod:
                        desired_dep_ids[int(dep_mod.get("id"))] = dep_item.optional
                    else:
                        missing_sources.append(dep_item.source_id)
                current_dep_map = self._current_dependency_map(ow_mod_id)
                for dep_id, optional in desired_dep_ids.items():
                    if current_dep_map.get(dep_id) != optional:
                        self.api.upsert_mod_dependency(ow_mod_id, dep_id, optional=optional)
                if self.prune and deps_ok and not missing_sources:
                    for dep_id in current_dep_map:
                        if dep_id not in desired_dep_ids:
                            self.api.delete_mod_dependency(ow_mod_id, dep_id)
                if not missing_sources:
                    with self._lock:
                        if self.pending_dependency_links.get(ow_mod_id) == info:
                            self.pending_dependency_links.pop(ow_mod_id, None)


class ConflictManager:
    def __init__(
        self,
        api: ApiClient,
        *,
        enabled: bool = True,
        prune: bool = True,
        enqueue_metadata: Callable[[str], None],
        lookup_mod: Callable[[str], Optional[Dict[str, Any]]],
        pending_conflict_links: Dict[int, Dict[str, Any]] | None = None,
        lock: threading.Lock | None = None,
    ) -> None:
        self.api = api
        self.enabled = enabled
        self.prune = prune
        self.enqueue_metadata = enqueue_metadata
        self.lookup_mod = lookup_mod
        self.pending_conflict_links = (
            pending_conflict_links if pending_conflict_links is not None else {}
        )
        self._lock = lock or threading.Lock()

    def clone(self, api: ApiClient) -> "ConflictManager":
        return ConflictManager(
            api,
            enabled=self.enabled,
            prune=self.prune,
            enqueue_metadata=self.enqueue_metadata,
            lookup_mod=self.lookup_mod,
            pending_conflict_links=self.pending_conflict_links,
            lock=self._lock,
        )

    def queue_missing_sources(self, conflict_source_ids: List[str]) -> None:
        if not self.enabled:
            return
        for conflict_source_id in conflict_source_ids:
            self.enqueue_metadata(str(conflict_source_id))

    def sync_conflicts(self, ow_mod_id: int, conflict_source_ids: List[str]) -> None:
        if not self.enabled:
            return
        with start_span(
            "conflicts.sync",
            {
                "ow.mod_id": ow_mod_id,
                "conflicts.desired_sources": len(conflict_source_ids),
                "conflicts.prune": self.prune,
            },
        ):
            desired_conflict_ids: List[int] = []
            missing_sources: List[str] = []
            for conflict_source_id in conflict_source_ids:
                conflict_source_id = str(conflict_source_id)
                conflict_mod = self.lookup_mod(conflict_source_id)
                if conflict_mod:
                    desired_conflict_ids.append(int(conflict_mod.get("id")))
                else:
                    missing_sources.append(conflict_source_id)
                    self.enqueue_metadata(conflict_source_id)

            current_conflict_ids = self.api.get_mod_conflicts(ow_mod_id)
            for conflict_id in desired_conflict_ids:
                if conflict_id not in current_conflict_ids:
                    self.api.add_mod_conflict(ow_mod_id, conflict_id)
            allow_prune = self.prune and not missing_sources
            if allow_prune:
                for conflict_id in current_conflict_ids:
                    if conflict_id not in desired_conflict_ids:
                        self.api.delete_mod_conflict(ow_mod_id, conflict_id)

            if missing_sources:
                with self._lock:
                    self.pending_conflict_links[ow_mod_id] = {
                        "conflicts": conflict_source_ids,
                    }
            else:
                with self._lock:
                    self.pending_conflict_links.pop(ow_mod_id, None)

    def retry_pending(self) -> None:
        with self._lock:
            pending_items = list(self.pending_conflict_links.items())
        if not pending_items:
            return
        with start_span(
            "conflicts.retry_pending",
            {"conflicts.pending_mods": len(pending_items)},
        ):
            for ow_mod_id, info in pending_items:
                conflict_source_ids = [str(dep) for dep in info.get("conflicts", [])]
                desired_conflict_ids: List[int] = []
                missing_sources: List[str] = []
                for conflict_source_id in conflict_source_ids:
                    conflict_mod = self.lookup_mod(conflict_source_id)
                    if conflict_mod:
                        desired_conflict_ids.append(int(conflict_mod.get("id")))
                    else:
                        missing_sources.append(conflict_source_id)
                current_conflict_ids = self.api.get_mod_conflicts(ow_mod_id)
                for conflict_id in desired_conflict_ids:
                    if conflict_id not in current_conflict_ids:
                        self.api.add_mod_conflict(ow_mod_id, conflict_id)
                allow_prune = self.prune and not missing_sources
                if allow_prune:
                    for conflict_id in current_conflict_ids:
                        if conflict_id not in desired_conflict_ids:
                            self.api.delete_mod_conflict(ow_mod_id, conflict_id)
                if not missing_sources:
                    with self._lock:
                        if self.pending_conflict_links.get(ow_mod_id) == info:
                            self.pending_conflict_links.pop(ow_mod_id, None)
