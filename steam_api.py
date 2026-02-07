import re
import time
from typing import Any, Dict, List

import requests


def steam_get_app_details(app_id: int, language: str, timeout: int) -> Dict[str, str]:
    url = "https://store.steampowered.com/api/appdetails"
    response = requests.get(
        url,
        params={"appids": app_id, "l": language},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    entry = payload.get(str(app_id), {})
    if not entry.get("success"):
        raise RuntimeError(f"Steam app {app_id} not found")
    data = entry.get("data", {})
    name = data.get("name", "")
    short_desc = data.get("short_description", "")
    full_desc = data.get("detailed_description", "")
    full_desc = re.sub(r"<[^>]+>", "", full_desc)
    return {
        "name": name,
        "short": short_desc,
        "description": full_desc,
    }


def steam_list_workshop_ids_html(
    app_id: int,
    max_pages: int,
    max_items: int,
    delay: float,
    language: str,
    timeout: int,
) -> List[str]:
    ids: List[str] = []
    seen = set()
    page = 1
    while True:
        if max_pages > 0 and page > max_pages:
            break
        url = "https://steamcommunity.com/workshop/browse/"
        params = {
            "appid": app_id,
            "browsesort": "mostrecent",
            "section": "readytouseitems",
            "p": page,
            "l": language,
        }
        response = requests.get(
            url,
            params=params,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=timeout,
        )
        if response.status_code != 200:
            break
        page_ids = re.findall(r"data-publishedfileid=\"(\d+)\"", response.text)
        if not page_ids:
            break
        for item_id in page_ids:
            if item_id in seen:
                continue
            seen.add(item_id)
            ids.append(item_id)
            if max_items > 0 and len(ids) >= max_items:
                return ids
        page += 1
        if delay > 0:
            time.sleep(delay)
    return ids


def steam_queryfiles_ids(
    app_id: int,
    api_key: str,
    max_pages: int,
    max_items: int,
    page_size: int,
    timeout: int,
) -> List[str]:
    ids: List[str] = []
    page = 1
    while True:
        if max_pages > 0 and page > max_pages:
            break
        params = {
            "key": api_key,
            "query_type": 1,
            "page": page,
            "numperpage": page_size,
            "appid": app_id,
            "return_details": 0,
        }
        response = requests.get(
            "https://api.steampowered.com/IPublishedFileService/QueryFiles/v1/",
            params=params,
            timeout=timeout,
        )
        if response.status_code != 200:
            break
        payload = response.json().get("response", {})
        entries = payload.get("publishedfiledetails")
        if entries is None:
            entries = payload.get("publishedfileids")
        page_ids: List[str] = []
        if isinstance(entries, list):
            for entry in entries:
                if isinstance(entry, dict):
                    file_id = entry.get("publishedfileid")
                else:
                    file_id = entry
                if file_id:
                    page_ids.append(str(file_id))
        if not page_ids:
            break
        ids.extend(page_ids)
        if max_items > 0 and len(ids) >= max_items:
            return ids[:max_items]
        total = payload.get("total")
        if total is not None and len(ids) >= int(total):
            break
        page += 1
    return ids


def steam_get_published_file_details(
    ids: List[str], timeout: int
) -> Dict[str, Dict[str, Any]]:
    if not ids:
        return {}
    params: Dict[str, Any] = {"itemcount": len(ids)}
    for idx, item_id in enumerate(ids):
        params[f"publishedfileids[{idx}]"] = item_id
    response = requests.post(
        "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/",
        data=params,
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json().get("response", {})
    details: Dict[str, Dict[str, Any]] = {}
    for entry in payload.get("publishedfiledetails", []):
        file_id = entry.get("publishedfileid")
        if file_id:
            details[str(file_id)] = entry
    return details


def steam_get_dependencies_with_key(
    ids: List[str], api_key: str, timeout: int
) -> Dict[str, List[str]]:
    if not ids:
        return {}
    params: Dict[str, Any] = {"key": api_key, "includechildren": 1}
    for idx, item_id in enumerate(ids):
        params[f"publishedfileids[{idx}]"] = item_id
    response = requests.get(
        "https://api.steampowered.com/IPublishedFileService/GetDetails/v1/",
        params=params,
        timeout=timeout,
    )
    if response.status_code != 200:
        return {}
    payload = response.json().get("response", {})
    deps: Dict[str, List[str]] = {}
    for entry in payload.get("publishedfiledetails", []):
        file_id = entry.get("publishedfileid")
        if not file_id:
            continue
        children = entry.get("children", [])
        dep_ids: List[str] = []
        for child in children:
            child_id = child.get("publishedfileid") or child.get("fileid")
            if child_id:
                dep_ids.append(str(child_id))
        deps[str(file_id)] = dep_ids
    return deps
