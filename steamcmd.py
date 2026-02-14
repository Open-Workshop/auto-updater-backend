import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from utils import ensure_dir


@dataclass(frozen=True)
class SteamDownloadResult:
    ok: bool
    reason: str | None = None


_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _extract_steamcmd_error(output: str) -> str | None:
    cleaned = _strip_ansi(output or "").replace("\r", "\n")
    specific_match = re.search(
        r"(ERROR!\s+Download item\s+\d+\s+failed\s+\([^)]+\)\.)",
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if specific_match:
        return " ".join(specific_match.group(1).split())
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "ERROR!" in line:
            return " ".join(line.split())
    return None


def download_steam_mod(
    steamcmd_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
) -> SteamDownloadResult:
    if not steamcmd_path.exists():
        logging.error("steamcmd not found at %s", steamcmd_path)
        return SteamDownloadResult(False, f"steamcmd not found at {steamcmd_path}")
    ensure_dir(steam_root)
    cmd = [
        str(steamcmd_path),
        "+force_install_dir",
        str(steam_root),
        "+login",
        "anonymous",
        "+workshop_download_item",
        str(app_id),
        str(workshop_id),
        "validate",
        "+quit",
    ]
    logging.info("SteamCMD download: app_id=%s workshop_id=%s", app_id, workshop_id)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    output = result.stdout or ""
    output_tail = _strip_ansi(output[-4000:])
    parsed_error = _extract_steamcmd_error(output)
    if result.returncode != 0:
        reason = parsed_error or f"steamcmd exit code {result.returncode}"
        logging.error(
            "SteamCMD failed for workshop %s: %s",
            workshop_id,
            reason,
        )
        if output_tail:
            logging.error("SteamCMD output tail for %s:\n%s", workshop_id, output_tail)
        return SteamDownloadResult(False, reason)
    if parsed_error:
        logging.error("SteamCMD reported failure for workshop %s: %s", workshop_id, parsed_error)
        return SteamDownloadResult(False, parsed_error)
    return SteamDownloadResult(True)
