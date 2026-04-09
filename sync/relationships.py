from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from core.telemetry import start_span
from ow.ow_api import ApiClient
from sync.metadata import OW_LOG


class TagManager:
    def __init__(
        self,
        api: ApiClient,
        game_id: int,
        page_size: int,
        *,
        enabled: bool,
        prune: bool,
    ) -> None:
        self.api = api
        self.game_id = game_id
        self.page_size = page_size
        self.enabled = enabled
        self.prune = prune
        self._name_to_id: Dict[str, int] = {}
        self._id_to_name: Dict[int, str] = {}

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
            for tag in self.api.list_tags(self.game_id, self.page_size):
                name = tag.get("name") or tag.get("tag_name")
                tag_id = tag.get("id") or tag.get("tag_id")
                if name and tag_id:
                    self._name_to_id[str(name).lower()] = int(tag_id)
                    self._id_to_name[int(tag_id)] = str(name)

    def sync_mod_tags(self, ow_mod_id: int, tag_names: List[str]) -> None:
        if not self.enabled:
            return
        with start_span(
            "tags.sync",
            {
                "ow.mod_id": ow_mod_id,
                "tags.desired": len(tag_names),
                "tags.prune": self.prune,
            },
        ):
            desired_tag_ids = self._resolve_tag_ids(tag_names)
            current_tag_ids = self.api.get_mod_tags(ow_mod_id)
            missing_tags = [tid for tid in desired_tag_ids if tid not in current_tag_ids]
            extra_tags = [tid for tid in current_tag_ids if tid not in desired_tag_ids]
            if missing_tags or extra_tags:
                OW_LOG.debug(
                    "OW mod %s tags: current=%s desired=%s add=%s prune=%s",
                    ow_mod_id,
                    len(current_tag_ids),
                    len(desired_tag_ids),
                    [self._id_to_name.get(tid, tid) for tid in missing_tags],
                    [self._id_to_name.get(tid, tid) for tid in extra_tags],
                )
            for tag_id in desired_tag_ids:
                if tag_id not in current_tag_ids:
                    self.api.add_mod_tag(ow_mod_id, tag_id)
            if self.prune:
                for tag_id in current_tag_ids:
                    if tag_id not in desired_tag_ids:
                        self.api.delete_mod_tag(ow_mod_id, tag_id)

    def _resolve_tag_ids(self, tag_names: List[str]) -> List[int]:
        desired_tag_ids: List[int] = []
        for tag_name in tag_names:
            key = tag_name.lower()
            tag_id = self._name_to_id.get(key)
            if not tag_id:
                try:
                    tag_id = self.api.add_tag(tag_name)
                except Exception as exc:
                    OW_LOG.warning("Failed to add tag %s: %s", tag_name, exc)
                    continue
                self.api.associate_game_tag(self.game_id, tag_id)
                self._name_to_id[key] = tag_id
                self._id_to_name[tag_id] = tag_name
            desired_tag_ids.append(tag_id)
        return desired_tag_ids


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
    ) -> None:
        self.api = api
        self.enabled = enabled
        self.prune = prune
        self.scrape_required_items = scrape_required_items
        self.enqueue_metadata = enqueue_metadata
        self.lookup_mod = lookup_mod
        self.pending_dependency_links: Dict[int, Dict[str, Any]] = {}

    def queue_missing_sources(self, dep_source_ids: List[str]) -> None:
        if not self.enabled or not self.scrape_required_items:
            return
        for dep_source_id in dep_source_ids:
            self.enqueue_metadata(str(dep_source_id))

    def sync_dependencies(
        self,
        ow_mod_id: int,
        dep_source_ids: List[str],
        deps_ok: bool,
    ) -> None:
        if not self.enabled or not self.scrape_required_items:
            return
        with start_span(
            "dependencies.sync",
            {
                "ow.mod_id": ow_mod_id,
                "deps.desired_sources": len(dep_source_ids),
                "deps.prune": self.prune,
                "deps.ok": deps_ok,
            },
        ):
            desired_dep_ids: List[int] = []
            missing_sources: List[str] = []
            for dep_source_id in dep_source_ids:
                dep_source_id = str(dep_source_id)
                dep_mod = self.lookup_mod(dep_source_id)
                if dep_mod:
                    desired_dep_ids.append(int(dep_mod.get("id")))
                else:
                    missing_sources.append(dep_source_id)
                    self.enqueue_metadata(dep_source_id)

            current_dep_ids = self.api.get_mod_dependencies(ow_mod_id)
            for dep_id in desired_dep_ids:
                if dep_id not in current_dep_ids:
                    self.api.add_mod_dependency(ow_mod_id, dep_id)

            allow_prune = self.prune and deps_ok and not missing_sources
            if allow_prune:
                for dep_id in current_dep_ids:
                    if dep_id not in desired_dep_ids:
                        self.api.delete_mod_dependency(ow_mod_id, dep_id)
            elif self.prune and not deps_ok:
                OW_LOG.debug(
                    "Skip dependency prune for %s due to Steam scrape failure",
                    ow_mod_id,
                )

            if missing_sources:
                self.pending_dependency_links[ow_mod_id] = {
                    "deps": dep_source_ids,
                    "deps_ok": deps_ok,
                }

    def retry_pending(self) -> None:
        if not self.pending_dependency_links:
            return
        with start_span(
            "dependencies.retry_pending",
            {"deps.pending_mods": len(self.pending_dependency_links)},
        ):
            for ow_mod_id, info in list(self.pending_dependency_links.items()):
                dep_source_ids = [str(dep) for dep in info.get("deps", [])]
                deps_ok = bool(info.get("deps_ok", True))
                desired_dep_ids: List[int] = []
                missing_sources: List[str] = []
                for dep_source_id in dep_source_ids:
                    dep_mod = self.lookup_mod(dep_source_id)
                    if dep_mod:
                        desired_dep_ids.append(int(dep_mod.get("id")))
                    else:
                        missing_sources.append(dep_source_id)
                current_dep_ids = self.api.get_mod_dependencies(ow_mod_id)
                for dep_id in desired_dep_ids:
                    if dep_id not in current_dep_ids:
                        self.api.add_mod_dependency(ow_mod_id, dep_id)
                if self.prune and deps_ok and not missing_sources:
                    for dep_id in current_dep_ids:
                        if dep_id not in desired_dep_ids:
                            self.api.delete_mod_dependency(ow_mod_id, dep_id)
                if not missing_sources:
                    self.pending_dependency_links.pop(ow_mod_id, None)
