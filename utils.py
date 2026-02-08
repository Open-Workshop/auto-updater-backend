import hashlib
import html
import json
import logging
import mimetypes
import os
import random
import re
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests

_DOWNLOAD_HTTP_RETRIES = 0
_DOWNLOAD_HTTP_BACKOFF = 0.0
_DOWNLOAD_RETRY_STATUSES = {429, 500, 502, 503, 504}


def set_download_request_policy(retries: int, backoff: float) -> None:
    global _DOWNLOAD_HTTP_RETRIES, _DOWNLOAD_HTTP_BACKOFF
    _DOWNLOAD_HTTP_RETRIES = max(0, int(retries))
    _DOWNLOAD_HTTP_BACKOFF = max(0.0, float(backoff))


def utc_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def has_files(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    return any(path.iterdir())


def strip_bbcode(text: str) -> str:
    text = re.sub(r"\[/?(b|i|u|h\d|hr)\]", "", text, flags=re.I)
    text = re.sub(r"\[img\]\s*(.*?)\s*\[/img\]", "", text, flags=re.I | re.S)
    text = re.sub(r"\[url=.*?\](.*?)\[/url\]", r"\1", text, flags=re.I | re.S)
    text = re.sub(r"\[/?\w+.*?\]", "", text, flags=re.I)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def truncate(text: str, limit: int) -> str:
    if limit <= 0:
        return ""
    if not text:
        return text or ""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore")


def normalize_image_url(url: str) -> str:
    if not url:
        return ""
    value = html.unescape(url.strip().strip("\"'"))
    if "?" in value:
        value = value.split("?", 1)[0]
    return value


def _image_fingerprint(url: str) -> str:
    normalized = normalize_image_url(url)
    if not normalized:
        return ""
    parsed = urlparse(normalized)
    host = (parsed.netloc or "").lower()
    if host.endswith(
        (
            "steamusercontent.com",
            "steamusercontent-a.akamaihd.net",
            "steamuserimages-a.akamaihd.net",
        )
    ):
        parts = [part for part in (parsed.path or "").split("/") if part]
        if parts:
            return parts[-1].lower()
    return normalized.lower()


def dedupe_images(urls: List[str]) -> List[str]:
    deduped: List[str] = []
    seen = set()
    for url in urls:
        fingerprint = _image_fingerprint(url)
        if not fingerprint or fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(url)
    return deduped


def parse_images(description: str, preview_url: str | None, max_images: int) -> List[str]:
    urls: List[str] = []
    if preview_url:
        urls.append(preview_url)
    deduped: List[str] = []
    seen = set()
    for url in urls:
        url = normalize_image_url(url)
        if not url or len(url) > 256:
            continue
        if url in seen:
            continue
        seen.add(url)
        deduped.append(url)
        if len(deduped) >= max_images:
            break
    return deduped


def zip_directory(source_dir: Path, dest_zip: Path) -> Path:
    ensure_dir(dest_zip.parent)
    if dest_zip.exists():
        dest_zip.unlink()
    with zipfile.ZipFile(dest_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for root, _, files in os.walk(source_dir):
            for name in files:
                full_path = Path(root) / name
                rel_path = full_path.relative_to(source_dir)
                archive.write(full_path, rel_path)
    return dest_zip


def _extension_from_headers(headers: Dict[str, str]) -> str:
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if not content_type:
        return ""
    ext = mimetypes.guess_extension(content_type) or ""
    if ext == ".jpe":
        ext = ".jpg"
    return ext


def _sleep_download_backoff(attempt: int, exc: Exception) -> None:
    if _DOWNLOAD_HTTP_BACKOFF <= 0:
        return
    delay = _DOWNLOAD_HTTP_BACKOFF * (2 ** (attempt - 1))
    delay += random.uniform(0.0, _DOWNLOAD_HTTP_BACKOFF)
    logging.warning(
        "Download retry %s/%s after error: %s (sleep %.1fs)",
        attempt,
        _DOWNLOAD_HTTP_RETRIES,
        exc,
        delay,
    )
    time.sleep(delay)


def download_url_to_file(url: str, dest_dir: Path, basename: str, timeout: int) -> Path | None:
    ensure_dir(dest_dir)
    attempts = _DOWNLOAD_HTTP_RETRIES + 1
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        response = None
        temp_path: Path | None = None
        try:
            response = requests.get(url, stream=True, timeout=timeout)
            if response.status_code in _DOWNLOAD_RETRY_STATUSES and attempt < attempts:
                retry_after = response.headers.get("retry-after")
                if retry_after:
                    try:
                        time.sleep(float(retry_after))
                    except ValueError:
                        pass
                _sleep_download_backoff(
                    attempt,
                    RuntimeError(f"HTTP {response.status_code}"),
                )
                continue
            if response.status_code != 200:
                logging.warning(
                    "Failed to download %s: %s",
                    url,
                    response.status_code,
                )
                return None
            ext = _extension_from_headers(response.headers)
            if not ext:
                ext = ".bin"
            path = dest_dir / f"{basename}{ext}"
            temp_path = path.with_suffix(f"{path.suffix}.part")
            with temp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
            temp_path.replace(path)
            return path
        except requests.RequestException as exc:
            last_exc = exc
            if attempt >= attempts:
                logging.warning("Failed to download %s: %s", url, exc)
                return None
            _sleep_download_backoff(attempt, exc)
            continue
        finally:
            if response is not None:
                response.close()
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
    if last_exc:
        logging.warning("Failed to download %s: %s", url, last_exc)
    return None


def download_url_to_file_with_hash(
    url: str, dest_dir: Path, basename: str, timeout: int
) -> tuple[Path | None, str | None]:
    ensure_dir(dest_dir)
    attempts = _DOWNLOAD_HTTP_RETRIES + 1
    last_exc: Exception | None = None
    for attempt in range(1, attempts + 1):
        response = None
        temp_path: Path | None = None
        try:
            response = requests.get(url, stream=True, timeout=timeout)
            if response.status_code in _DOWNLOAD_RETRY_STATUSES and attempt < attempts:
                retry_after = response.headers.get("retry-after")
                if retry_after:
                    try:
                        time.sleep(float(retry_after))
                    except ValueError:
                        pass
                _sleep_download_backoff(
                    attempt,
                    RuntimeError(f"HTTP {response.status_code}"),
                )
                continue
            if response.status_code != 200:
                logging.warning(
                    "Failed to download %s: %s",
                    url,
                    response.status_code,
                )
                return None, None
            ext = _extension_from_headers(response.headers)
            if not ext:
                ext = ".bin"
            path = dest_dir / f"{basename}{ext}"
            temp_path = path.with_suffix(f"{path.suffix}.part")
            hasher = hashlib.sha256()
            with temp_path.open("wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    hasher.update(chunk)
                    handle.write(chunk)
            temp_path.replace(path)
            return path, hasher.hexdigest()
        except requests.RequestException as exc:
            last_exc = exc
            if attempt >= attempts:
                logging.warning("Failed to download %s: %s", url, exc)
                return None, None
            _sleep_download_backoff(attempt, exc)
            continue
        finally:
            if response is not None:
                response.close()
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                except FileNotFoundError:
                    pass
    if last_exc:
        logging.warning("Failed to download %s: %s", url, last_exc)
    return None, None


def load_state(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"version": 2, "mods": {}}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or "mods" not in data:
            raise ValueError("Invalid state format")
        if data.get("version") != 2:
            data = {"version": 2, "mods": {}}
        return data
    except Exception:
        return {"version": 2, "mods": {}}


def save_state(path: Path, state: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, ensure_ascii=True, indent=2, sort_keys=True)
    temp_path.replace(path)
