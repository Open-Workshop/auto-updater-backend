import json
import logging
import random
import time
from typing import Any, Dict, List, Optional

import requests

from utils import truncate

_DEFAULT_LIMITS: Dict[str, int] = {
    "game_name": 128,
    "game_short_desc": 256,
    "game_desc": 10000,
    "mod_name": 128,
    "mod_short_description": 256,
    "mod_description": 10000,
    "tag_name": 128,
}
_LIMITS: Dict[str, int] = dict(_DEFAULT_LIMITS)


def _limit(key: str, fallback: int) -> int:
    try:
        value = int(_LIMITS.get(key, fallback))
    except (TypeError, ValueError):
        return fallback
    return value if value > 0 else fallback


def _extract_limits(openapi: Dict[str, Any]) -> Dict[str, int]:
    wanted = {
        "game_name",
        "game_short_desc",
        "game_desc",
        "mod_name",
        "mod_short_description",
        "mod_description",
        "tag_name",
    }
    found: Dict[str, int] = {}
    schemas = openapi.get("components", {}).get("schemas", {})
    if not isinstance(schemas, dict):
        return found
    for schema in schemas.values():
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            continue
        for key, prop in props.items():
            if key not in wanted or not isinstance(prop, dict):
                continue
            limit = prop.get("maxLength")
            try:
                limit_value = int(limit)
            except (TypeError, ValueError):
                continue
            if limit_value <= 0:
                continue
            current = found.get(key)
            if current is None or limit_value < current:
                found[key] = limit_value
    return found


def load_api_limits(api: "ApiClient") -> None:
    global _LIMITS
    try:
        response = api.request("get", "/openapi.json")
    except Exception as exc:
        logging.warning("Failed to load OW OpenAPI limits: %s", exc)
        return
    if not _is_success(response):
        logging.warning(
            "Failed to load OW OpenAPI limits: %s %s",
            response.status_code,
            (response.text or "")[:200],
        )
        return
    try:
        payload = response.json()
    except Exception as exc:
        logging.warning("Failed to parse OW OpenAPI limits: %s", exc)
        return
    limits = _extract_limits(payload)
    if not limits:
        logging.warning("OW OpenAPI limits not found, using defaults")
        return
    _LIMITS = {**_LIMITS, **limits}
    logging.info(
        "Loaded OW limits: mod_name=%s short_desc=%s desc=%s",
        _LIMITS.get("mod_name"),
        _LIMITS.get("mod_short_description"),
        _LIMITS.get("mod_description"),
    )


class ApiClient:
    def __init__(
        self,
        base_url: str,
        login: str,
        password: str,
        timeout: int,
        retries: int = 3,
        retry_backoff: float = 1.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.login_name = login
        self.password = password
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "openworkshop-mirror/2.0"})
        self._retry_statuses = {500, 502, 503, 504}

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
        files = kwargs.get("files")

        def reset_files() -> None:
            if not files:
                return
            for value in files.values():
                file_obj = None
                if isinstance(value, tuple):
                    if len(value) >= 2:
                        file_obj = value[1]
                else:
                    file_obj = value
                if file_obj is None:
                    continue
                seek = getattr(file_obj, "seek", None)
                if callable(seek):
                    try:
                        seek(0)
                    except Exception:
                        pass

        attempts = self.retries + 1
        last_exc: Exception | None = None
        for attempt in range(1, attempts + 1):
            if attempt > 1:
                reset_files()
            try:
                response = self.session.request(
                    method, url, timeout=self.timeout, **kwargs
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt >= attempts:
                    raise
                self._sleep_backoff(attempt, method, url, exc)
                continue

            if response.status_code in (401, 403):
                logging.warning("Session expired, re-authenticating")
                self.login()
                if attempt > 1:
                    reset_files()
                response = self.session.request(
                    method, url, timeout=self.timeout, **kwargs
                )

            if response.status_code in self._retry_statuses and attempt < attempts:
                self._sleep_backoff(
                    attempt,
                    method,
                    url,
                    RuntimeError(f"HTTP {response.status_code}"),
                )
                continue

            return response

        if last_exc:
            raise last_exc
        return response

    def _sleep_backoff(self, attempt: int, method: str, url: str, exc: Exception) -> None:
        if self.retry_backoff <= 0:
            return
        delay = self.retry_backoff * (2 ** (attempt - 1))
        delay += random.uniform(0.0, self.retry_backoff)
        logging.warning(
            "HTTP retry %s/%s after error for %s %s: %s (sleep %.1fs)",
            attempt,
            self.retries,
            method.upper(),
            url,
            exc,
            delay,
        )
        time.sleep(delay)


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


def _is_success(response: requests.Response) -> bool:
    return 200 <= response.status_code < 300


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


def ow_find_mod_by_source(api: ApiClient, source: str, source_id: int) -> Optional[int]:
    params = {
        "page_size": 10,
        "page": 0,
        "general": "true",
        "dates": "true",
        "primary_sources": json.dumps([source]),
        "allowed_sources_ids": json.dumps([source_id]),
    }
    response = api.request("get", "/list/mods/", params=params)
    if not _is_success(response):
        return None
    payload = response.json()
    results = payload.get("results", []) if isinstance(payload, dict) else []
    for item in results:
        if not isinstance(item, dict):
            continue
        if str(item.get("source_id")) == str(source_id):
            mod_id = item.get("id")
            if mod_id is not None:
                try:
                    return int(mod_id)
                except (TypeError, ValueError):
                    return None
    return None


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
            "game_name": truncate(name, _limit("game_name", 128)),
            "game_short_desc": truncate(short_desc, _limit("game_short_desc", 256)),
            "game_desc": truncate(desc, _limit("game_desc", 10000)),
        },
    )
    if not _is_success(response):
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
    if not _is_success(response):
        logging.warning(
            "Failed to update game source: %s %s",
            response.status_code,
            (response.text or "")[:200],
        )


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
            "mod_name": truncate(name, _limit("mod_name", 128)),
            "mod_short_description": truncate(short_desc, _limit("mod_short_description", 256)),
            "mod_description": truncate(desc, _limit("mod_description", 10000)),
            "mod_source": source,
            "mod_source_id": source_id,
            "mod_game": game_id,
            "mod_public": public_mode,
            "without_author": "true" if without_author else "false",
        }
        response = api.request("post", "/add/mod", data=data, files=files)
    if response.status_code == 412:
        existing_id = ow_find_mod_by_source(api, source, source_id)
        if existing_id is not None:
            return existing_id
        raise RuntimeError(f"Failed to add mod: {response.status_code} {response.text}")
    if not _is_success(response):
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
    set_source: bool = True,
) -> None:
    data = {
        "mod_id": mod_id,
        "mod_name": truncate(name, _limit("mod_name", 128)),
        "mod_short_description": truncate(short_desc, _limit("mod_short_description", 256)),
        "mod_description": truncate(desc, _limit("mod_description", 10000)),
        "mod_game": game_id,
        "mod_public": public_mode,
    }
    if set_source:
        data["mod_source"] = source
        data["mod_source_id"] = source_id
    if file_path:
        with file_path.open("rb") as handle:
            files = {"mod_file": (file_path.name, handle)}
            response = api.request("post", "/edit/mod", data=data, files=files)
    else:
        response = api.request("post", "/edit/mod", data=data)
    if not _is_success(response):
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
    response = api.request(
        "post",
        "/add/tag",
        data={"tag_name": truncate(name, _limit("tag_name", 128))},
    )
    if not _is_success(response):
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
    if not _is_success(response) and response.status_code != 409:
        logging.warning(
            "Failed to associate tag %s with game %s: %s %s",
            tag_id,
            game_id,
            response.status_code,
            (response.text or "")[:200],
        )


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
    if not _is_success(response):
        logging.warning(
            "Failed to add tag %s to mod %s: %s %s",
            tag_id,
            mod_id,
            response.status_code,
            (response.text or "")[:200],
        )


def ow_delete_mod_tag(api: ApiClient, mod_id: int, tag_id: int) -> None:
    response = api.request("delete", f"/mods/{mod_id}/tags/{tag_id}")
    if not _is_success(response):
        logging.warning(
            "Failed to delete tag %s from mod %s: %s %s",
            tag_id,
            mod_id,
            response.status_code,
            (response.text or "")[:200],
        )


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
    if not _is_success(response):
        logging.warning(
            "Failed to add dependency %s to mod %s: %s %s",
            dep_id,
            mod_id,
            response.status_code,
            (response.text or "")[:200],
        )


def ow_delete_mod_dependency(api: ApiClient, mod_id: int, dep_id: int) -> bool:
    response = api.request("delete", f"/mods/{mod_id}/dependencies/{dep_id}")
    if _is_success(response) or response.status_code in (404, 409, 412):
        return True
    logging.warning(
        "Failed to delete dependency %s from mod %s: %s %s",
        dep_id,
        mod_id,
        response.status_code,
        (response.text or "")[:200],
    )
    return False


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
    if not _is_success(response):
        logging.warning(
            "Failed to add resource %s to %s %s: %s %s",
            url,
            owner_type,
            owner_id,
            response.status_code,
            (response.text or "")[:200],
        )


def ow_add_resource_file(
    api: ApiClient,
    owner_type: str,
    owner_id: int,
    res_type: str,
    file_path,
) -> bool:
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
    if not _is_success(response) and response.status_code != 409:
        logging.warning(
            "Failed to add resource file %s to %s %s: %s %s",
            file_path,
            owner_type,
            owner_id,
            response.status_code,
            (response.text or "")[:200],
        )
        return False
    return True


def ow_delete_resource(api: ApiClient, resource_id: int) -> None:
    response = api.request("delete", f"/resources/{resource_id}")
    if not _is_success(response):
        logging.warning(
            "Failed to delete resource %s: %s %s",
            resource_id,
            response.status_code,
            (response.text or "")[:200],
        )
