from __future__ import annotations

import json
import logging
import random
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import requests

from utils import truncate

_DEFAULT_LIMITS: Dict[str, int] = {
    "game_name": 127,
    "game_short_desc": 255,
    "game_desc": 9999,
    "mod_name": 127,
    "mod_short_description": 255,
    "mod_description": 9999,
    "tag_name": 127,
}


class OWLimits:
    def __init__(self, defaults: Dict[str, int]) -> None:
        self._defaults = dict(defaults)
        self._limits = dict(defaults)

    def limit(self, key: str, fallback: int | None = None) -> int:
        if fallback is None:
            fallback = self._defaults.get(key, 0)
        try:
            value = int(self._limits.get(key, fallback))
        except (TypeError, ValueError):
            return fallback
        return value if value > 0 else fallback

    def update_from_openapi(self, openapi: Dict[str, Any]) -> bool:
        limits = _extract_limits(openapi)
        if not limits:
            return False
        self._limits = {**self._limits, **limits}
        return True

    def limit_mod_fields(
        self,
        name: str,
        short_desc: str,
        description: str,
    ) -> tuple[str, str, str]:
        name = truncate(name, self.limit("mod_name", _DEFAULT_LIMITS["mod_name"]))
        short_desc = truncate(
            short_desc,
            self.limit("mod_short_description", _DEFAULT_LIMITS["mod_short_description"]),
        )
        description = truncate(
            description,
            self.limit("mod_description", _DEFAULT_LIMITS["mod_description"]),
        )
        return name, short_desc, description

    def limit_game_fields(self, name: str, short_desc: str, desc: str) -> tuple[str, str, str]:
        return (
            truncate(name, self.limit("game_name", _DEFAULT_LIMITS["game_name"])),
            truncate(short_desc, self.limit("game_short_desc", _DEFAULT_LIMITS["game_short_desc"])),
            truncate(desc, self.limit("game_desc", _DEFAULT_LIMITS["game_desc"])),
        )

    def limit_tag_name(self, name: str) -> str:
        return truncate(name, self.limit("tag_name", _DEFAULT_LIMITS["tag_name"]))

    def cap_limit(self, key: str, value: int) -> None:
        try:
            new_limit = int(value)
        except (TypeError, ValueError):
            return
        if new_limit <= 0:
            return
        current = self._limits.get(key, self._defaults.get(key))
        if current is None or new_limit < int(current):
            self._limits[key] = new_limit


_GLOBAL_LIMITS = OWLimits(_DEFAULT_LIMITS)


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


class OWClient:
    def __init__(
        self,
        base_url: str,
        login: str,
        password: str,
        timeout: int,
        *,
        retries: int = 3,
        retry_backoff: float = 1.0,
        limits: OWLimits | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.login_name = login
        self.password = password
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.retry_backoff = max(0.0, float(retry_backoff))
        self.limits = limits or _GLOBAL_LIMITS
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

    @staticmethod
    def _is_name_too_long_message(message: str | None) -> bool:
        if not message:
            return False
        lower = message.lower()
        if "name" in lower and "too long" in lower:
            return True
        if "назв" in lower and "длин" in lower:
            return True
        return False

    def _fallback_name_limits(self, current_limit: int) -> List[int]:
        candidates = [
            int(current_limit * 0.8),
            int(current_limit * 0.6),
            64,
            48,
            32,
        ]
        result: List[int] = []
        for value in candidates:
            if value <= 0 or value >= current_limit:
                continue
            if value not in result:
                result.append(value)
        return result

    def _retry_mod_name(
        self,
        request_fn: Callable[[str], requests.Response],
        name: str,
        response: requests.Response,
    ) -> requests.Response:
        if response.status_code != 413 or not self._is_name_too_long_message(response.text):
            return response
        current_limit = self.limits.limit("mod_name", _DEFAULT_LIMITS["mod_name"])
        for new_limit in self._fallback_name_limits(current_limit):
            truncated = truncate(name, new_limit)
            if not truncated or truncated == name:
                continue
            logging.warning(
                "OW mod_name too long, retrying with limit %s (was %s)",
                new_limit,
                current_limit,
            )
            new_response = request_fn(truncated)
            if (
                new_response.status_code == 413
                and self._is_name_too_long_message(new_response.text)
            ):
                response = new_response
                continue
            if self.is_success(new_response):
                self.limits.cap_limit("mod_name", new_limit)
            return new_response
        return response

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

    def load_limits(self) -> bool:
        try:
            response = self.request("get", "/openapi.json")
        except Exception as exc:
            logging.warning("Failed to load OW OpenAPI limits: %s", exc)
            return False
        if not self.is_success(response):
            logging.warning(
                "Failed to load OW OpenAPI limits: %s %s",
                response.status_code,
                (response.text or "")[:200],
            )
            return False
        try:
            payload = response.json()
        except Exception as exc:
            logging.warning("Failed to parse OW OpenAPI limits: %s", exc)
            return False
        if not self.limits.update_from_openapi(payload):
            logging.warning("OW OpenAPI limits not found, using defaults")
            return False
        logging.info(
            "Loaded OW limits: mod_name=%s short_desc=%s desc=%s",
            self.limits.limit("mod_name"),
            self.limits.limit("mod_short_description"),
            self.limits.limit("mod_description"),
        )
        return True

    def limit_mod_fields(
        self, name: str, short_desc: str, description: str
    ) -> tuple[str, str, str]:
        return self.limits.limit_mod_fields(name, short_desc, description)

    def list_mods(self, game_id: int, page_size: int) -> List[Dict[str, Any]]:
        def fetch(page: int) -> Dict[str, Any]:
            params = {
                "page_size": page_size,
                "page": page,
                "general": "true",
                "dates": "true",
                "game": game_id,
                "primary_sources": json.dumps(["steam"]),
            }
            response = self.request("get", "/list/mods/", params=params)
            if response.status_code >= 500:
                params.pop("primary_sources", None)
                response = self.request("get", "/list/mods/", params=params)
            response.raise_for_status()
            return response.json()

        return list_all_pages(fetch)

    def get_mod_by_source(self, source: str, source_id: int) -> Optional[Dict[str, Any]]:
        params = {
            "page_size": 10,
            "page": 0,
            "general": "true",
            "dates": "true",
            "primary_sources": json.dumps([source]),
            "allowed_sources_ids": json.dumps([source_id]),
        }
        response = self.request("get", "/list/mods/", params=params)
        if not self.is_success(response):
            return None
        payload = response.json()
        results = payload.get("results", []) if isinstance(payload, dict) else []
        for item in results:
            if not isinstance(item, dict):
                continue
            if str(item.get("source_id")) == str(source_id):
                return item
        return None

    def get_mods_by_source_ids(
        self, source: str, source_ids: List[int], page_size: int = 50
    ) -> List[Dict[str, Any]]:
        if not source_ids:
            return []
        size = max(page_size, len(source_ids))
        params = {
            "page_size": size,
            "page": 0,
            "general": "true",
            "dates": "true",
            "primary_sources": json.dumps([source]),
            "allowed_sources_ids": json.dumps(source_ids),
        }
        response = self.request("get", "/list/mods/", params=params)
        if response.status_code >= 500:
            params.pop("primary_sources", None)
            response = self.request("get", "/list/mods/", params=params)
        if not self.is_success(response):
            return []
        payload = response.json()
        results = payload.get("results", []) if isinstance(payload, dict) else []
        return [item for item in results if isinstance(item, dict)]

    def find_mod_by_source(self, source: str, source_id: int) -> Optional[int]:
        params = {
            "page_size": 10,
            "page": 0,
            "general": "true",
            "dates": "true",
            "primary_sources": json.dumps([source]),
            "allowed_sources_ids": json.dumps([source_id]),
        }
        response = self.request("get", "/list/mods/", params=params)
        if not self.is_success(response):
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

    def list_games_by_source(self, app_id: int, page_size: int) -> List[Dict[str, Any]]:
        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
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

    def get_game(self, game_id: int) -> Dict[str, Any]:
        response = self.request("get", f"/games/{game_id}")
        if response.status_code == 404:
            raise RuntimeError("Game not found")
        response.raise_for_status()
        return response.json()

    def add_game(self, name: str, short_desc: str, desc: str) -> int:
        name, short_desc, desc = self.limits.limit_game_fields(name, short_desc, desc)
        response = self.request(
            "post",
            "/add/game",
            data={
                "game_name": name,
                "game_short_desc": short_desc,
                "game_desc": desc,
            },
        )
        if not self.is_success(response):
            raise RuntimeError(
                f"Failed to add game: {response.status_code} {response.text}"
            )
        game_id = self.extract_id(response)
        if game_id is not None:
            return game_id
        raise RuntimeError("Failed to parse game id from response")

    def edit_game_source(self, game_id: int, source: str, source_id: int) -> None:
        response = self.request(
            "post",
            "/edit/game",
            data={
                "game_id": game_id,
                "game_source": source,
                "game_source_id": source_id,
            },
        )
        if not self.is_success(response):
            logging.warning(
                "Failed to update game source: %s %s",
                response.status_code,
                (response.text or "")[:200],
            )

    def get_mod_details(self, mod_id: int) -> Dict[str, Any]:
        response = self.request(
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

    @staticmethod
    def _redirect_location(response: requests.Response) -> Optional[str]:
        location = response.headers.get("Location") or response.headers.get("location")
        if not location:
            return None
        return urljoin(response.url, location)

    def _upload_file_to_storage(
        self,
        redirect_response: requests.Response,
        file_path,
    ) -> requests.Response:
        upload_url = self._redirect_location(redirect_response)
        if not upload_url:
            raise RuntimeError("Storage redirect does not contain Location header")
        with file_path.open("rb") as handle:
            return self.session.request(
                "post",
                upload_url,
                data=handle,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-File-Name": file_path.name,
                },
                timeout=self.timeout,
                allow_redirects=False,
            )

    def _find_mod_by_source_with_wait(
        self,
        source: str,
        source_id: int,
        *,
        attempts: int = 6,
        delay: float = 1.0,
    ) -> Optional[int]:
        attempts = max(1, int(attempts))
        for idx in range(attempts):
            mod_id = self.find_mod_by_source(source, source_id)
            if mod_id is not None:
                return mod_id
            if idx + 1 < attempts:
                time.sleep(max(0.0, float(delay)))
        return None

    def add_mod(
        self,
        name: str,
        short_desc: str,
        desc: str,
        source: str,
        source_id: int,
        game_id: int,
        public_mode: int,
        without_author: bool,
        file_path,
        *,
        return_created: bool = False,
    ) -> int | tuple[int, bool]:
        name, short_desc, desc = self.limits.limit_mod_fields(name, short_desc, desc)

        def _result(mod_id: int, created: bool) -> int | tuple[int, bool]:
            if return_created:
                return mod_id, created
            return mod_id

        def send(mod_name: str) -> requests.Response:
            data = {
                "mod_name": mod_name,
                "mod_short_description": short_desc,
                "mod_description": desc,
                "mod_source": source,
                "mod_source_id": source_id,
                "mod_game": game_id,
                "mod_public": public_mode,
                "without_author": "true" if without_author else "false",
            }
            return self.request(
                "post",
                "/mods/from-file",
                data=data,
                allow_redirects=False,
            )

        response = send(name)
        if response.status_code == 412:
            existing_id = self._find_mod_by_source_with_wait(source, source_id)
            if existing_id is not None:
                return _result(existing_id, False)
            raise RuntimeError(
                f"Failed to add mod: {response.status_code} {response.text}"
            )
        response = self._retry_mod_name(send, name, response)
        if response.status_code == 412:
            existing_id = self._find_mod_by_source_with_wait(source, source_id)
            if existing_id is not None:
                return _result(existing_id, False)
            raise RuntimeError(
                f"Failed to add mod: {response.status_code} {response.text}"
            )
        if response.status_code == 307:
            upload_response = self._upload_file_to_storage(response, file_path)
            if not self.is_success(upload_response):
                raise RuntimeError(
                    "Failed to upload mod file: "
                    f"{upload_response.status_code} {upload_response.text}"
                )
        elif not self.is_success(response):
            raise RuntimeError(
                f"Failed to add mod: {response.status_code} {response.text}"
            )
        mod_id = self.extract_id(response)
        if mod_id is not None:
            return _result(mod_id, True)
        mod_id = self._find_mod_by_source_with_wait(source, source_id)
        if mod_id is not None:
            return _result(mod_id, True)
        raise RuntimeError("Failed to parse mod id from response")

    def upsert_mod_with_file(
        self,
        name: str,
        short_desc: str,
        desc: str,
        source: str,
        source_id: int,
        game_id: int,
        public_mode: int,
        without_author: bool,
        file_path,
    ) -> tuple[int, bool]:
        existing_id = self.find_mod_by_source(source, source_id)
        if existing_id is not None:
            self.edit_mod(
                existing_id,
                name,
                short_desc,
                desc,
                source,
                source_id,
                game_id,
                public_mode,
                file_path,
                set_source=False,
            )
            return int(existing_id), False

        add_result = self.add_mod(
            name,
            short_desc,
            desc,
            source,
            source_id,
            game_id,
            public_mode,
            without_author,
            file_path,
            return_created=True,
        )
        if isinstance(add_result, tuple):
            mod_id, created = add_result
        else:
            mod_id, created = int(add_result), True
        if created:
            return int(mod_id), True

        # If add hit source conflict (412), ensure file is uploaded to the existing mod.
        self.edit_mod(
            int(mod_id),
            name,
            short_desc,
            desc,
            source,
            source_id,
            game_id,
            public_mode,
            file_path,
            set_source=False,
        )
        return int(mod_id), False

    def edit_mod(
        self,
        mod_id: int,
        name: str,
        short_desc: str,
        desc: str,
        source: str,
        source_id: int,
        game_id: int,
        public_mode: int,
        file_path=None,
        *,
        set_source: bool = True,
    ) -> None:
        name, short_desc, desc = self.limits.limit_mod_fields(name, short_desc, desc)

        def send(mod_name: str) -> requests.Response:
            data = {
                "mod_id": mod_id,
                "mod_name": mod_name,
                "mod_short_description": short_desc,
                "mod_description": desc,
                "mod_game": game_id,
                "mod_public": public_mode,
            }
            if set_source:
                data["mod_source"] = source
                data["mod_source_id"] = source_id
            return self.request("post", "/edit/mod", data=data)

        response = send(name)
        response = self._retry_mod_name(send, name, response)
        if not self.is_success(response):
            raise RuntimeError(
                f"Failed to edit mod {mod_id}: {response.status_code} {response.text}"
            )
        if file_path:
            file_response = self.request(
                "post",
                f"/mods/{mod_id}/file",
                data={},
                allow_redirects=False,
            )
            if file_response.status_code == 307:
                upload_response = self._upload_file_to_storage(file_response, file_path)
                if not self.is_success(upload_response):
                    raise RuntimeError(
                        f"Failed to update mod file {mod_id}: "
                        f"{upload_response.status_code} {upload_response.text}"
                    )
            elif not self.is_success(file_response):
                raise RuntimeError(
                    f"Failed to start mod file update {mod_id}: "
                    f"{file_response.status_code} {file_response.text}"
                )

    def list_tags(self, game_id: int, page_size: int) -> List[Dict[str, Any]]:
        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
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

    def add_tag(self, name: str) -> int:
        response = self.request(
            "post",
            "/add/tag",
            data={"tag_name": self.limits.limit_tag_name(name)},
        )
        if not self.is_success(response):
            raise RuntimeError(
                f"Failed to add tag: {response.status_code} {response.text}"
            )
        tag_id = self.extract_id(response)
        if tag_id is not None:
            return tag_id
        raise RuntimeError("Failed to parse tag id from response")

    def associate_game_tag(self, game_id: int, tag_id: int) -> None:
        response = self.request(
            "post",
            "/association/game/tag",
            data={"game_id": game_id, "tag_id": tag_id, "mode": "true"},
        )
        if not self.is_success(response) and response.status_code != 409:
            logging.warning(
                "Failed to associate tag %s with game %s: %s %s",
                tag_id,
                game_id,
                response.status_code,
                (response.text or "")[:200],
            )

    def get_mod_tags(self, mod_id: int) -> List[int]:
        response = self.request("get", f"/mods/{mod_id}/tags")
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

    def add_mod_tag(self, mod_id: int, tag_id: int) -> None:
        response = self.request("post", f"/mods/{mod_id}/tags/{tag_id}")
        if not self.is_success(response):
            logging.warning(
                "Failed to add tag %s to mod %s: %s %s",
                tag_id,
                mod_id,
                response.status_code,
                (response.text or "")[:200],
            )

    def delete_mod_tag(self, mod_id: int, tag_id: int) -> None:
        response = self.request("delete", f"/mods/{mod_id}/tags/{tag_id}")
        if not self.is_success(response):
            logging.warning(
                "Failed to delete tag %s from mod %s: %s %s",
                tag_id,
                mod_id,
                response.status_code,
                (response.text or "")[:200],
            )

    def get_mod_dependencies(self, mod_id: int) -> List[int]:
        response = self.request("get", f"/mods/{mod_id}/dependencies")
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

    def add_mod_dependency(self, mod_id: int, dep_id: int) -> None:
        response = self.request("post", f"/mods/{mod_id}/dependencies/{dep_id}")
        if not self.is_success(response):
            logging.warning(
                "Failed to add dependency %s to mod %s: %s %s",
                dep_id,
                mod_id,
                response.status_code,
                (response.text or "")[:200],
            )

    def delete_mod_dependency(self, mod_id: int, dep_id: int) -> bool:
        response = self.request("delete", f"/mods/{mod_id}/dependencies/{dep_id}")
        if self.is_success(response) or response.status_code in (404, 409, 412):
            return True
        logging.warning(
            "Failed to delete dependency %s from mod %s: %s %s",
            dep_id,
            mod_id,
            response.status_code,
            (response.text or "")[:200],
        )
        return False

    def get_mod_resources(self, mod_id: int) -> List[Dict[str, Any]]:
        response = self.request("get", f"/mods/{mod_id}/resources")
        if response.status_code == 404:
            return []
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            return payload.get("results", [])
        return []

    def add_resource(
        self, owner_type: str, owner_id: int, res_type: str, url: str
    ) -> None:
        response = self.request(
            "post",
            f"/add/resource/{owner_type}",
            data={
                "resource_type": res_type,
                "resource_url": url,
                "resource_owner_id": owner_id,
            },
        )
        if not self.is_success(response):
            logging.warning(
                "Failed to add resource %s to %s %s: %s %s",
                url,
                owner_type,
                owner_id,
                response.status_code,
                (response.text or "")[:200],
            )

    def add_resource_file(
        self,
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
            response = self.request(
                "post",
                f"/add/resource/{owner_type}",
                data=data,
                files=files,
            )
        if not self.is_success(response) and response.status_code != 409:
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

    def delete_resource(self, resource_id: int) -> None:
        response = self.request("delete", f"/resources/{resource_id}")
        if not self.is_success(response):
            logging.warning(
                "Failed to delete resource %s: %s %s",
                resource_id,
                response.status_code,
                (response.text or "")[:200],
            )

    @staticmethod
    def extract_id(response: requests.Response) -> Optional[int]:
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

    @staticmethod
    def is_success(response: requests.Response) -> bool:
        return 200 <= response.status_code < 300

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


class ApiClient(OWClient):
    pass


def load_api_limits(api: OWClient) -> None:
    api.load_limits()


def ow_limit_mod_fields(
    name: str,
    short_desc: str,
    description: str,
) -> tuple[str, str, str]:
    return _GLOBAL_LIMITS.limit_mod_fields(name, short_desc, description)


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


def ow_list_mods(api: OWClient, game_id: int, page_size: int) -> List[Dict[str, Any]]:
    return api.list_mods(game_id, page_size)


def ow_find_mod_by_source(api: OWClient, source: str, source_id: int) -> Optional[int]:
    return api.find_mod_by_source(source, source_id)


def ow_get_mod_by_source(
    api: OWClient, source: str, source_id: int
) -> Optional[Dict[str, Any]]:
    return api.get_mod_by_source(source, source_id)


def ow_list_games_by_source(
    api: OWClient, app_id: int, page_size: int
) -> List[Dict[str, Any]]:
    return api.list_games_by_source(app_id, page_size)


def ow_get_game(api: OWClient, game_id: int) -> Dict[str, Any]:
    return api.get_game(game_id)


def ow_add_game(api: OWClient, name: str, short_desc: str, desc: str) -> int:
    return api.add_game(name, short_desc, desc)


def ow_edit_game_source(api: OWClient, game_id: int, source: str, source_id: int) -> None:
    api.edit_game_source(game_id, source, source_id)


def ow_get_mod_details(api: OWClient, mod_id: int) -> Dict[str, Any]:
    return api.get_mod_details(mod_id)


def ow_add_mod(
    api: OWClient,
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
    return api.add_mod(
        name,
        short_desc,
        desc,
        source,
        source_id,
        game_id,
        public_mode,
        without_author,
        file_path,
    )


def ow_edit_mod(
    api: OWClient,
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
    api.edit_mod(
        mod_id,
        name,
        short_desc,
        desc,
        source,
        source_id,
        game_id,
        public_mode,
        file_path,
        set_source=set_source,
    )


def ow_list_tags(api: OWClient, game_id: int, page_size: int) -> List[Dict[str, Any]]:
    return api.list_tags(game_id, page_size)


def ow_add_tag(api: OWClient, name: str) -> int:
    return api.add_tag(name)


def ow_associate_game_tag(api: OWClient, game_id: int, tag_id: int) -> None:
    api.associate_game_tag(game_id, tag_id)


def ow_get_mod_tags(api: OWClient, mod_id: int) -> List[int]:
    return api.get_mod_tags(mod_id)


def ow_add_mod_tag(api: OWClient, mod_id: int, tag_id: int) -> None:
    api.add_mod_tag(mod_id, tag_id)


def ow_delete_mod_tag(api: OWClient, mod_id: int, tag_id: int) -> None:
    api.delete_mod_tag(mod_id, tag_id)


def ow_get_mod_dependencies(api: OWClient, mod_id: int) -> List[int]:
    return api.get_mod_dependencies(mod_id)


def ow_add_mod_dependency(api: OWClient, mod_id: int, dep_id: int) -> None:
    api.add_mod_dependency(mod_id, dep_id)


def ow_delete_mod_dependency(api: OWClient, mod_id: int, dep_id: int) -> bool:
    return api.delete_mod_dependency(mod_id, dep_id)


def ow_get_mod_resources(api: OWClient, mod_id: int) -> List[Dict[str, Any]]:
    return api.get_mod_resources(mod_id)


def ow_add_resource(
    api: OWClient, owner_type: str, owner_id: int, res_type: str, url: str
) -> None:
    api.add_resource(owner_type, owner_id, res_type, url)


def ow_add_resource_file(
    api: OWClient,
    owner_type: str,
    owner_id: int,
    res_type: str,
    file_path,
) -> bool:
    return api.add_resource_file(owner_type, owner_id, res_type, file_path)


def ow_delete_resource(api: OWClient, resource_id: int) -> None:
    api.delete_resource(resource_id)
