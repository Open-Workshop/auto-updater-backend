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


def _extract_depotdownloader_error(output: str) -> str | None:
    """Extract error message from DepotDownloader output."""
    cleaned = (output or "").replace("\r", "\n")
    
    # Look for common error patterns
    error_patterns = [
        r"Error:\s+(.+)",
        r"ERROR:\s+(.+)",
        r"Exception:\s+(.+)",
        r"Failed to download.+?:\s*(.+)",
    ]
    
    for pattern in error_patterns:
        match = re.search(pattern, cleaned, re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    
    # If no specific error found, look for lines with "error" or "failed"
    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(keyword in line.lower() for keyword in ["error", "failed", "exception"]):
            return line
    
    return None


def _is_retryable_reason(reason: str | None, returncode: int) -> bool:
    """Determine if a download error is retryable."""
    if not reason:
        return returncode != 0
    
    normalized = reason.lower()
    retryable_keywords = [
        "timeout",
        "connection",
        "network",
        "download failed",
        "failed (failure)",
    ]
    
    return any(keyword in normalized for keyword in retryable_keywords)


def _workshop_path(steam_root: Path, app_id: int, workshop_id: int) -> Path:
    """Get the path where workshop content is stored."""
    return (
        steam_root
        / "steamapps"
        / "workshop"
        / "content"
        / str(app_id)
        / str(workshop_id)
    )


def _clear_workshop_cache(
    steam_root: Path,
    app_id: int,
    workshop_id: int,
    reason: str,
) -> None:
    """Clear workshop cache for a specific item."""
    workshop_root = steam_root / "steamapps" / "workshop"
    targets = (
        workshop_root / f"appworkshop_{app_id}.acf",
        workshop_root / "downloads" / str(app_id),
        workshop_root / "temp" / str(app_id),
        _workshop_path(steam_root, app_id, workshop_id),
    )
    
    removed: list[str] = []
    for target in targets:
        try:
            if not target.exists():
                continue
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
            removed.append(str(target))
        except (FileNotFoundError, OSError) as exc:
            logging.warning("Failed to remove cache path %s: %s", target, exc)
    
    if removed:
        logging.info(
            "Workshop cache cleanup for %s (%s): removed=%s",
            workshop_id,
            reason,
            ", ".join(removed),
        )


def download_steam_mod(
    depotdownloader_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
) -> SteamDownloadResult:
    """Download a Steam workshop mod using DepotDownloader."""
    if not depotdownloader_path.exists():
        logging.error("DepotDownloader not found at %s", depotdownloader_path)
        return SteamDownloadResult(
            False,
            f"DepotDownloader not found at {depotdownloader_path}",
            retryable=False,
        )
    
    workshop_content_dir = (
        steam_root
        / "steamapps"
        / "workshop"
        / "content"
        / str(app_id)
    )
    ensure_dir(workshop_content_dir)
    
    cmd = [
        str(depotdownloader_path),
        "-app", str(app_id),
        "-pubfile", str(workshop_id),
        "-dir", str(workshop_content_dir),
        "-validate",
    ]
    
    logging.info("DepotDownloader download: app_id=%s workshop_id=%s", app_id, workshop_id)
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3600,  # 1 hour timeout
        )
    except subprocess.TimeoutExpired:
        return SteamDownloadResult(
            False,
            "DepotDownloader timeout after 1 hour",
            retryable=True,
        )
    
    output = result.stdout or ""
    stderr = result.stderr or ""
    full_output = f"{output}\n{stderr}"
    
    # Log output for debugging
    if full_output:
        logging.info("DepotDownloader output for workshop %s:\n%s", workshop_id, full_output[-4000:])
    
    parsed_error = _extract_depotdownloader_error(full_output)
    
    if result.returncode != 0:
        reason = parsed_error or f"DepotDownloader exit code {result.returncode}"
        retryable = _is_retryable_reason(reason, result.returncode)
        logging.error("DepotDownloader failed for workshop %s: %s", workshop_id, reason)
        
        if retryable:
            _clear_workshop_cache(steam_root, app_id, workshop_id, reason)
        
        return SteamDownloadResult(
            False,
            reason,
            retryable=retryable,
            diagnostics=full_output[-2000:] if full_output else None,
        )
    
    if parsed_error:
        retryable = _is_retryable_reason(parsed_error, result.returncode)
        logging.error("DepotDownloader error for workshop %s: %s", workshop_id, parsed_error)
        
        if retryable:
            _clear_workshop_cache(steam_root, app_id, workshop_id, parsed_error)
        
        return SteamDownloadResult(
            False,
            parsed_error,
            retryable=retryable,
            diagnostics=full_output[-2000:] if full_output else None,
        )
    
    return SteamDownloadResult(True)


def _download_remote_archive(
    runner_url: str,
    app_id: int,
    workshop_id: int,
    dest_zip: Path,
) -> SteamDownloadResult:
    """Download mod archive from a remote runner service."""
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
    depotdownloader_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
    dest_zip: Path,
    runner_url: str | None = None,
) -> SteamDownloadResult:
    """Download a mod archive, either from remote runner or locally."""
    if runner_url:
        return _download_remote_archive(runner_url, app_id, workshop_id, dest_zip)
    
    result = download_steam_mod(depotdownloader_path, steam_root, app_id, workshop_id)
    if not result.ok:
        return result
    
    workshop_path = _workshop_path(steam_root, app_id, workshop_id)
    if not has_files(workshop_path):
        reason = f"DepotDownloader finished but no files found at {workshop_path}"
        logging.error(reason)
        return SteamDownloadResult(False, reason=reason, retryable=False)
    
    archive_path = zip_directory(workshop_path, dest_zip)
    return SteamDownloadResult(True, archive_path=archive_path)
