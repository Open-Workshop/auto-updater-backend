from __future__ import annotations

"""Compatibility exports for sync support helpers."""

from sync.metadata import (
    DEPOTDOWNLOADER_MAX_DOWNLOAD_ATTEMPTS,
    DEPOTDOWNLOADER_RETRY_BACKOFF_SECONDS,
    OW_LOG,
    PARSER_LOG,
    STEAM_LOG,
    SteamModLoader,
    ensure_game,
    ow_last_edit_ts,
    ow_recent_edit,
    parse_ow_datetime,
    recent_edit_window_label,
)
from sync.relationships import DependencyManager, TagManager
from sync.resources import (
    ImageHashes,
    ResourceSyncer,
    build_hashes,
    hash_matches_any,
    hashes_match,
)
