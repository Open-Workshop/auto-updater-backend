import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from core.utils import ensure_dir
from core.utils import has_files, zip_directory


@dataclass(frozen=True)
class SteamDownloadResult:
    ok: bool
    reason: str | None = None
    retryable: bool = False
    archive_path: Path | None = None
    diagnostics: str | None = None


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


def _is_retryable_reason(reason: str | None, returncode: int) -> bool:
    if reason:
        normalized = reason.lower()
        if "failed (failure)" in normalized:
            return True
        if "timeout" in normalized:
            return True
    return returncode != 0


def _read_tail_lines(path: Path, max_bytes: int = 512 * 1024) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read().decode("utf-8", errors="ignore")
    except OSError:
        return []
    return [line.strip() for line in data.splitlines() if line.strip()]


def _collect_steam_diagnostics(workshop_id: int) -> str | None:
    wid = str(workshop_id)
    log_dir = Path.home() / "Steam" / "logs"
    workshop_lines = _read_tail_lines(log_dir / "workshop_log.txt")
    content_lines = _read_tail_lines(log_dir / "content_log.txt")
    details: list[str] = []

    if workshop_lines:
        req_indexes = [
            idx
            for idx, line in enumerate(workshop_lines)
            if f"Download item {wid} requested by app" in line
        ]
        if req_indexes:
            start = req_indexes[-1]
            window = workshop_lines[start : start + 120]
        else:
            window = workshop_lines[-160:]
        result_line = next(
            (
                line
                for line in window
                if f"Download item {wid} result :" in line
            ),
            None,
        )
        if result_line:
            details.append(result_line)
        canceled_line = next(
            (
                line
                for line in window
                if "Update canceled:" in line
            ),
            None,
        )
        if canceled_line:
            details.append(canceled_line)

    if content_lines:
        missing_file_re = re.compile(
            rf'Validation: missing file "{re.escape(wid)}\\([^"]+)"'
        )
        missing_count = 0
        missing_examples: list[str] = []
        for line in content_lines:
            match = missing_file_re.search(line)
            if not match:
                continue
            missing_count += 1
            if len(missing_examples) < 3:
                missing_examples.append(match.group(1).replace("\\", "/"))
        if missing_count:
            examples = ", ".join(missing_examples)
            details.append(
                f"Validation missing files: {missing_count} (examples: {examples})"
            )
            quick_scan = next(
                (
                    line
                    for line in reversed(content_lines)
                    if "Validation: quick scan" in line
                ),
                None,
            )
            if quick_scan:
                details.append(quick_scan)

    if not details:
        return None
    return " | ".join(details)


def _remove_cache_path(path: Path, reason: str) -> bool:
    try:
        if not path.exists():
            return False
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        logging.warning("Failed to remove Steam cache path %s (%s): %s", path, reason, exc)
        return False


def download_steam_mod(
    steamcmd_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
) -> SteamDownloadResult:
    if not steamcmd_path.exists():
        logging.error("steamcmd not found at %s", steamcmd_path)
        return SteamDownloadResult(
            False,
            f"steamcmd not found at {steamcmd_path}",
            retryable=False,
        )
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
        timeout=3600,  # 1 hour timeout for workshop downloads
    )
    output = result.stdout or ""
    output_tail = _strip_ansi(output[-4000:])
    parsed_error = _extract_steamcmd_error(output)
    
    # Log SteamCMD output for both success and failure cases
    if output_tail:
        logging.info("SteamCMD output for workshop %s:\n%s", workshop_id, output_tail)
    
    if result.returncode != 0:
        diagnostics = _collect_steam_diagnostics(workshop_id)
        reason = parsed_error or f"steamcmd exit code {result.returncode}"
        retryable = _is_retryable_reason(reason, result.returncode)
        logging.error(
            "SteamCMD failed for workshop %s: %s",
            workshop_id,
            reason,
        )
        if diagnostics:
            logging.error("SteamCMD diagnostics for workshop %s: %s", workshop_id, diagnostics)
        if retryable:
            _clear_steam_workshop_cache(steam_root, app_id, workshop_id, reason)
        return SteamDownloadResult(
            False,
            reason,
            retryable=retryable,
            diagnostics=diagnostics,
        )
    if parsed_error:
        diagnostics = _collect_steam_diagnostics(workshop_id)
        retryable = _is_retryable_reason(parsed_error, result.returncode)
        if diagnostics:
            logging.error("SteamCMD diagnostics for workshop %s: %s", workshop_id, diagnostics)
        if retryable:
            _clear_steam_workshop_cache(steam_root, app_id, workshop_id, parsed_error)
        return SteamDownloadResult(
            False,
            parsed_error,
            retryable=retryable,
            diagnostics=diagnostics,
        )
    return SteamDownloadResult(True)


def _workshop_path(steam_root: Path, app_id: int, workshop_id: int) -> Path:
    return (
        steam_root
        / "steamapps"
        / "workshop"
        / "content"
        / str(app_id)
        / str(workshop_id)
    )


def _clear_steam_workshop_cache(
    steam_root: Path,
    app_id: int,
    workshop_id: int,
    reason: str,
) -> None:
    workshop_root = steam_root / "steamapps" / "workshop"
    targets = (
        workshop_root / f"appworkshop_{app_id}.acf",
        workshop_root / "downloads" / str(app_id),
        workshop_root / "temp" / str(app_id),
        _workshop_path(steam_root, app_id, workshop_id),
    )
    removed: list[str] = []
    for target in targets:
        if _remove_cache_path(target, reason):
            removed.append(str(target))
    if removed:
        logging.info(
            "Steam cache cleanup for workshop %s (%s): removed=%s",
            workshop_id,
            reason,
            ", ".join(removed),
        )


def _download_remote_archive(
    runner_url: str,
    app_id: int,
    workshop_id: int,
    dest_zip: Path,
) -> SteamDownloadResult:
    ensure_dir(dest_zip.parent)
    temp_path = dest_zip.with_suffix(f"{dest_zip.suffix}.part")
    endpoint = runner_url.rstrip("/") + "/api/v1/archive"
    response: requests.Response | None = None
    try:
        response = requests.post(
            endpoint,
            json={"appId": app_id, "workshopId": workshop_id},
            timeout=(15, 1800),
            stream=True,
        )
        if response.status_code != 200:
            try:
                payload: dict[str, Any] = response.json()
            except ValueError:
                payload = {}
            reason = str(payload.get("reason") or f"runner returned HTTP {response.status_code}")
            diagnostics = payload.get("diagnostics")
            return SteamDownloadResult(
                False,
                reason=reason,
                retryable=bool(payload.get("retryable", False)),
                diagnostics=str(diagnostics) if diagnostics else None,
            )
        with temp_path.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                handle.write(chunk)
        temp_path.replace(dest_zip)
        return SteamDownloadResult(True, archive_path=dest_zip)
    except requests.RequestException as exc:
        return SteamDownloadResult(False, reason=str(exc), retryable=True)
    finally:
        if response is not None:
            response.close()
        if temp_path.exists():
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def download_mod_archive(
    steamcmd_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
    dest_zip: Path,
    runner_url: str | None = None,
) -> SteamDownloadResult:
    if runner_url:
        return _download_remote_archive(runner_url, app_id, workshop_id, dest_zip)
    result = download_steam_mod(steamcmd_path, steam_root, app_id, workshop_id)
    if not result.ok:
        return result
    workshop_path = _workshop_path(steam_root, app_id, workshop_id)
    if not has_files(workshop_path):
        reason = f"steamcmd finished but no files found at {workshop_path}"
        logging.error(reason)
        return SteamDownloadResult(False, reason=reason, retryable=False)
    archive_path = zip_directory(workshop_path, dest_zip)
    return SteamDownloadResult(True, archive_path=archive_path)
