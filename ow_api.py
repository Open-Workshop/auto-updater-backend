import json
import logging
from typing import Any, Dict, List, Optional

import requests

from utils import truncate


class ApiClient:
    def __init__(self, base_url: str, login: str, password: str, timeout: int) -> None:
        self.base_url = base_url.rstrip("/")
        self.login_name = login
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "openworkshop-mirror/2.0"})

    def login(self) -> None:
        if not self.login_name or not self.password:
            raise RuntimeError("Missing OW_LOGIN or OW_PASSWORD environment variables")
        url = f"{self.base_url}/session/password"
        response = self.session.post(
            url,
            data={"login": self.login_name, "password": self.password},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Login failed: {response.status_code} {response.text[:200]}"
            )

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.base_url}{path}"
        response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        if response.status_code in (401, 403):
            logging.warning("Session expired, re-authenticating")
            self.login()
            response = self.session.request(
                method, url, timeout=self.timeout, **kwargs
            )
        return response


def _extract_id(response: requests.Response) -> Optional[int]:
    try:
        payload = response.json()
    except Exception:
        payload = None
    if isinstance(payload, dict):
        for key in ("id", "tag_id", "mod_id", "game_id", "resource_id"):
            if key in payload and payload[key] is not None:
                try:
                    return int(payload[key])
                except (TypeError, ValueError):
                    continue
    if isinstance(payload, int):
        return int(payload)
    if isinstance(payload, str):
        text = payload.strip()
    else:
        text = (response.text or "").strip()
    if text.isdigit():
        return int(text)
    return None


def list_all_pages(fetch_page: callable) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    page = 0
    while True:
        payload = fetch_page(page)
        page_results = payload.get("results", [])
        results.extend(page_results)
        total = payload.get("database_size")
        if not page_results:
            break
        if total is not None and len(results) >= int(total):
            break
        page += 1
    return results


def ow_list_mods(api: ApiClient, game_id: int, page_size: int) -> List[Dict[str, Any]]:
    def fetch(page: int) -> Dict[str, Any]:
        params = {
            "page_size": page_size,
            "page": page,
            "general": "true",
            "dates": "true",
            "game": game_id,
            "primary_sources": json.dumps(["steam"]),
        }
        response = api.request("get", "/list/mods/", params=params)
        if response.status_code >= 500:
            params.pop("primary_sources", None)
            response = api.request("get", "/list/mods/", params=params)
        response.raise_for_status()
        return response.json()

    return list_all_pages(fetch)


def ow_list_games_by_source(api: ApiClient, app_id: int, page_size: int) -> List[Dict[str, Any]]:
    def fetch(page: int) -> Dict[str, Any]:
        response = api.request(
            "get",
            "/list/games/",
            params={
                "page_size": page_size,
                "page": page,
                "primary_sources": json.dumps(["steam"]),
                "allowed_sources_ids": json.dumps([app_id]),
            },
        )
        response.raise_for_status()
        return response.json()

    return list_all_pages(fetch)


def ow_get_game(api: ApiClient, game_id: int) -> Dict[str, Any]:
    response = api.request("get", f"/games/{game_id}")
    if response.status_code == 404:
        raise RuntimeError("Game not found")
    response.raise_for_status()
    return response.json()


def ow_add_game(api: ApiClient, name: str, short_desc: str, desc: str) -> int:
    response = api.request(
        "post",
        "/add/game",
        data={
            "game_name": truncate(name, 128),
            "game_short_desc": truncate(short_desc, 256),
            "game_desc": truncate(desc, 10000),
        },
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(f"Failed to add game: {response.status_code} {response.text}")
    game_id = _extract_id(response)
    if game_id is not None:
        return game_id
    raise RuntimeError("Failed to parse game id from response")


def ow_edit_game_source(api: ApiClient, game_id: int, source: str, source_id: int) -> None:
    response = api.request(
        "post",
        "/edit/game",
        data={
            "game_id": game_id,
            "game_source": source,
            "game_source_id": source_id,
        },
    )
    if response.status_code not in (200, 204):
        logging.warning("Failed to update game source: %s", response.status_code)


def ow_get_mod_details(api: ApiClient, mod_id: int) -> Dict[str, Any]:
    response = api.request(
        "get",
        f"/mods/{mod_id}",
        params={
            "short_description": "true",
            "description": "true",
            "general": "true",
            "game": "true",
        },
    )
    response.raise_for_status()
    return response.json()


def ow_add_mod(
    api: ApiClient,
    name: str,
    short_desc: str,
    desc: str,
    source: str,
    source_id: int,
    game_id: int,
    public_mode: int,
    without_author: bool,
    file_path,
) -> int:
    with file_path.open("rb") as handle:
        files = {"mod_file": (file_path.name, handle)}
        data = {
            "mod_name": truncate(name, 128),
            "mod_short_description": truncate(short_desc, 256),
            "mod_description": truncate(desc, 10000),
            "mod_source": source,
            "mod_source_id": source_id,
            "mod_game": game_id,
            "mod_public": public_mode,
            "without_author": "true" if without_author else "false",
        }
        response = api.request("post", "/add/mod", data=data, files=files)
    if response.status_code not in (200, 201):
        raise RuntimeError(f"Failed to add mod: {response.status_code} {response.text}")
    mod_id = _extract_id(response)
    if mod_id is not None:
        return mod_id
    raise RuntimeError("Failed to parse mod id from response")


def ow_edit_mod(
    api: ApiClient,
    mod_id: int,
    name: str,
    short_desc: str,
    desc: str,
    source: str,
    source_id: int,
    game_id: int,
    public_mode: int,
    file_path=None,
) -> None:
    data = {
        "mod_id": mod_id,
        "mod_name": truncate(name, 128),
        "mod_short_description": truncate(short_desc, 256),
        "mod_description": truncate(desc, 10000),
        "mod_source": source,
        "mod_source_id": source_id,
        "mod_game": game_id,
        "mod_public": public_mode,
    }
    if file_path:
        with file_path.open("rb") as handle:
            files = {"mod_file": (file_path.name, handle)}
            response = api.request("post", "/edit/mod", data=data, files=files)
    else:
        response = api.request("post", "/edit/mod", data=data)
    if response.status_code not in (200, 204):
        raise RuntimeError(
            f"Failed to edit mod {mod_id}: {response.status_code} {response.text}"
        )


def ow_list_tags(api: ApiClient, game_id: int, page_size: int) -> List[Dict[str, Any]]:
    def fetch(page: int) -> Dict[str, Any]:
        response = api.request(
            "get",
            "/tags",
            params={
                "game_id": game_id,
                "page_size": page_size,
                "page": page,
            },
        )
        response.raise_for_status()
        return response.json()

    return list_all_pages(fetch)


def ow_add_tag(api: ApiClient, name: str) -> int:
    response = api.request("post", "/add/tag", data={"tag_name": truncate(name, 128)})
    if response.status_code not in (200, 201, 202):
        raise RuntimeError(f"Failed to add tag: {response.status_code} {response.text}")
    tag_id = _extract_id(response)
    if tag_id is not None:
        return tag_id
    raise RuntimeError("Failed to parse tag id from response")


def ow_associate_game_tag(api: ApiClient, game_id: int, tag_id: int) -> None:
    response = api.request(
        "post",
        "/association/game/tag",
        data={"game_id": game_id, "tag_id": tag_id, "mode": "true"},
    )
    if response.status_code not in (200, 202, 204, 409):
        logging.warning("Failed to associate tag %s with game %s", tag_id, game_id)


def ow_get_mod_tags(api: ApiClient, mod_id: int) -> List[int]:
    response = api.request("get", f"/mods/{mod_id}/tags")
    if response.status_code == 404:
        return []
    response.raise_for_status()
    payload = response.json()
    tag_ids: List[int] = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                tag_id = item.get("id") or item.get("tag_id")
            else:
                tag_id = item
            if tag_id is not None:
                tag_ids.append(int(tag_id))
    return tag_ids


def ow_add_mod_tag(api: ApiClient, mod_id: int, tag_id: int) -> None:
    response = api.request("post", f"/mods/{mod_id}/tags/{tag_id}")
    if response.status_code not in (200, 201, 202, 204):
        logging.warning("Failed to add tag %s to mod %s", tag_id, mod_id)


def ow_delete_mod_tag(api: ApiClient, mod_id: int, tag_id: int) -> None:
    response = api.request("delete", f"/mods/{mod_id}/tags/{tag_id}")
    if response.status_code not in (200, 204):
        logging.warning("Failed to delete tag %s from mod %s", tag_id, mod_id)


def ow_get_mod_dependencies(api: ApiClient, mod_id: int) -> List[int]:
    response = api.request("get", f"/mods/{mod_id}/dependencies")
    if response.status_code == 404:
        return []
    response.raise_for_status()
    payload = response.json()
    results = payload.get("results", []) if isinstance(payload, dict) else []
    dep_ids: List[int] = []
    for item in results:
        if isinstance(item, dict):
            dep_id = item.get("id") or item.get("mod_id") or item.get("dependencie")
        else:
            dep_id = item
        if dep_id is not None:
            dep_ids.append(int(dep_id))
    return dep_ids


def ow_add_mod_dependency(api: ApiClient, mod_id: int, dep_id: int) -> None:
    response = api.request("post", f"/mods/{mod_id}/dependencies/{dep_id}")
    if response.status_code not in (200, 201, 202, 204):
        logging.warning("Failed to add dependency %s to mod %s", dep_id, mod_id)


def ow_delete_mod_dependency(api: ApiClient, mod_id: int, dep_id: int) -> None:
    response = api.request("delete", f"/mods/{mod_id}/dependencies/{dep_id}")
    if response.status_code not in (200, 204):
        logging.warning("Failed to delete dependency %s from mod %s", dep_id, mod_id)


def ow_get_mod_resources(api: ApiClient, mod_id: int) -> List[Dict[str, Any]]:
    response = api.request("get", f"/mods/{mod_id}/resources")
    if response.status_code == 404:
        return []
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict):
        return payload.get("results", [])
    return []


def ow_add_resource(api: ApiClient, owner_type: str, owner_id: int, res_type: str, url: str) -> None:
    response = api.request(
        "post",
        f"/add/resource/{owner_type}",
        data={
            "resource_type": res_type,
            "resource_url": url,
            "resource_owner_id": owner_id,
        },
    )
    if response.status_code not in (200, 201, 202, 204):
        logging.warning("Failed to add resource %s to %s %s", url, owner_type, owner_id)


def ow_add_resource_file(api: ApiClient, owner_type: str, owner_id: int, res_type: str, file_path) -> None:
    with file_path.open("rb") as handle:
        files = {"resource_file": (file_path.name, handle)}
        data = {
            "resource_type": res_type,
            "resource_owner_id": owner_id,
        }
        response = api.request(
            "post",
            f"/add/resource/{owner_type}",
            data=data,
            files=files,
        )
    if response.status_code not in (200, 201, 202, 204):
        logging.warning("Failed to add resource file %s to %s %s", file_path, owner_type, owner_id)


def ow_delete_resource(api: ApiClient, resource_id: int) -> None:
    response = api.request("delete", f"/resources/{resource_id}")
    if response.status_code not in (200, 204):
        logging.warning("Failed to delete resource %s", resource_id)
