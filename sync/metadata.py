from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

from core.log_tags import tagged_logger
from core.telemetry import start_span
from ow.ow_api import ApiClient
from steam.steam_api import steam_get_app_details
from steam.steam_mod import SteamMod


OW_LOG = tagged_logger("ow")
STEAM_LOG = tagged_logger("steam")
PARSER_LOG = tagged_logger("parser")

RECENT_OW_EDIT_SECONDS = 7 * 24 * 60 * 60
DEPOTDOWNLOADER_MAX_DOWNLOAD_ATTEMPTS = 3
DEPOTDOWNLOADER_RETRY_BACKOFF_SECONDS = 5.0


def recent_edit_window_label(seconds: int = RECENT_OW_EDIT_SECONDS) -> str:
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


class SteamModLoader:
    def __init__(self, timeout: int, language: str) -> None:
        self.timeout = int(timeout)
        self.language = language

    def load_batch(self, item_ids: List[str]) -> Dict[str, SteamMod]:
        if not item_ids:
            return {}
        STEAM_LOG.info("Steam batch load: items=%s", len(item_ids))
        with start_span(
            "steam.load_batch",
            {
                "steam.items": len(item_ids),
                "steam.language": self.language,
            },
        ):
            return asyncio.run(self._load_sequential(item_ids))

    async def _load_sequential(self, item_ids: List[str]) -> Dict[str, SteamMod]:
        timeout_cfg = aiohttp.ClientTimeout(total=self.timeout)
        results: Dict[str, SteamMod] = {}
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            total = len(item_ids)
            for idx, item_id in enumerate(item_ids, start=1):
                start = time.monotonic()
                STEAM_LOG.info("Steam load %s/%s id=%s", idx, total, item_id)
                mod = SteamMod(item_id)
                ok = await mod.load(
                    timeout=self.timeout,
                    session=session,
                    language=self.language,
                )
                elapsed = time.monotonic() - start
                if not ok:
                    STEAM_LOG.warning(
                        "Steam page parse failed for %s (%.2fs)",
                        item_id,
                        elapsed,
                    )
                    continue
                STEAM_LOG.debug("Steam page loaded %s (%.2fs)", item_id, elapsed)
                results[str(item_id)] = mod
        return results


def ensure_game(
    api: ApiClient,
    game_id: Optional[int],
    steam_app_id: int,
    language: str,
    timeout: int,
) -> int:
    with start_span(
        "ensure_game.resolve_or_create",
        {
            "ow.game_id": game_id or 0,
            "steam.app_id": steam_app_id,
            "steam.language": language,
        },
    ):
        if game_id:
            try:
                game = api.get_game(game_id)
            except Exception as exc:
                OW_LOG.warning("Game %s not found: %s", game_id, exc)
            else:
                source_id = game.get("source_id")
                if source_id and int(source_id) != steam_app_id:
                    OW_LOG.warning(
                        "OW game source_id %s does not match steam app id %s",
                        source_id,
                        steam_app_id,
                    )
                return game_id

        games = api.list_games_by_source(steam_app_id, 50)
        if games:
            return int(games[0]["id"])

        app_details = steam_get_app_details(steam_app_id, language, timeout)
        game_id = api.add_game(
            app_details["name"],
            app_details["short"],
            app_details["description"],
        )
        api.edit_game_source(game_id, "steam", steam_app_id)
        return game_id


def parse_ow_datetime(value: str | None) -> int:
    if not value:
        return 0
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def ow_last_edit_ts(ow_mod: Optional[Dict[str, Any]]) -> int:
    if not ow_mod:
        return 0
    latest = 0
    for key in ("date_edit", "date_update_file", "date_creation"):
        value = ow_mod.get(key)
        if not isinstance(value, str):
            continue
        ts = parse_ow_datetime(value)
        if ts > latest:
            latest = ts
    return latest


def ow_recent_edit(
    ow_mod: Optional[Dict[str, Any]],
    now_ts: int | None = None,
) -> bool:
    last_ts = ow_last_edit_ts(ow_mod)
    if last_ts <= 0:
        return False
    if now_ts is None:
        now_ts = int(time.time())
    return (now_ts - last_ts) < RECENT_OW_EDIT_SECONDS
