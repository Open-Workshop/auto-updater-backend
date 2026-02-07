import json
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


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
    if len(text) <= limit:
        return text
    return text[:limit]


def parse_images(description: str, preview_url: str | None, max_images: int) -> List[str]:
    urls: List[str] = []
    if preview_url:
        urls.append(preview_url)
    for match in re.findall(r"\[img\]\s*(https?://[^\s\]]+)\s*\[/img\]", description, re.I):
        urls.append(match)
    deduped: List[str] = []
    seen = set()
    for url in urls:
        url = url.strip()
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
