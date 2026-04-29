from __future__ import annotations

import asyncio
import base64
import json
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from core.telemetry import start_span
from core.utils import truncate

_DEFAULT_LIMITS: Dict[str, int] = {
    "game_name": 128,
    "game_short_desc": 256,
    "game_desc": 10000,
    "mod_name": 128,
    "mod_short_description": 256,
    "mod_description": 10000,
    "tag_name": 128,
}

_UPLOAD_WS_IDLE_TIMEOUT_MIN = 300.0
_UPLOAD_WS_IDLE_TIMEOUT_FACTOR = 5.0
_UPLOAD_WATCHDOG_POLL_SECONDS = 5.0


@dataclass(frozen=True)
class StorageTransfer:
    transfer_url: str
    ws_url: str | None = None


@dataclass(frozen=True)
class StorageUploadResponse:
    status_code: int
    text: str
    headers: Dict[str, str]


@dataclass(frozen=True)
class StorageProgressUpdate:
    stage: str
    percent: int | None
    sent_bytes: int | None
    total_bytes: int | None
    explicit_percent: bool


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
    found: Dict[str, int] = {}
    schemas = openapi.get("components", {}).get("schemas", {})
    if not isinstance(schemas, dict):
        return found
    for schema_name, schema in schemas.items():
        if not isinstance(schema, dict):
            continue
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            continue
        for key, prop in props.items():
            if not isinstance(prop, dict):
                continue
            limit = prop.get("maxLength")
            try:
                limit_value = int(limit)
            except (TypeError, ValueError):
                continue
            if limit_value <= 0:
                continue

            mapped_key: str | None = None
            if schema_name.startswith("Game"):
                if key == "name":
                    mapped_key = "game_name"
                elif key == "short_description":
                    mapped_key = "game_short_desc"
                elif key == "description":
                    mapped_key = "game_desc"
            elif schema_name.startswith("Mod"):
                if key == "name":
                    mapped_key = "mod_name"
                elif key == "short_description":
                    mapped_key = "mod_short_description"
                elif key == "description":
                    mapped_key = "mod_description"
            elif schema_name.startswith("Tag") and key == "name":
                mapped_key = "tag_name"

            if mapped_key is None:
                continue
            current = found.get(mapped_key)
            if current is None or limit_value < current:
                found[mapped_key] = limit_value
    return found


def _response_items(payload: Any) -> list[Any]:
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return items
        results = payload.get("results")
        if isinstance(results, list):
            return results
    if isinstance(payload, list):
        return payload
    return []


def _response_total(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    pagination = payload.get("pagination")
    if isinstance(pagination, dict):
        total = pagination.get("total")
        try:
            if total is None:
                return None
            return int(total)
        except (TypeError, ValueError):
            return None
    total = payload.get("database_size")
    try:
        if total is None:
            return None
        return int(total)
    except (TypeError, ValueError):
        return None


def _clamp_page_size(page_size: int) -> int:
    try:
        value = int(page_size)
    except (TypeError, ValueError):
        value = 1
    return max(1, min(value, 50))


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
        url = f"{self.base_url}/sessions"
        response = self.session.post(
            url,
            json={"method": "password", "login": self.login_name, "password": self.password},
            timeout=self.timeout,
        )
        if response.status_code not in {200, 201}:
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
                    except (OSError, ValueError):
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
                response.close()
                logging.warning("Session expired, re-authenticating")
                self.login()
                if attempt > 1:
                    reset_files()
                response = self.session.request(
                    method, url, timeout=self.timeout, **kwargs
                )

            if response.status_code in self._retry_statuses and attempt < attempts:
                response.close()
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
        except (requests.RequestException, RuntimeError) as exc:
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
        except ValueError as exc:
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
                "page_size": _clamp_page_size(page_size),
                "page": page,
                "game_id": game_id,
                "include": ["dates"],
            }
            response = self.request("get", "/mods", params=params)
            response.raise_for_status()
            return response.json()

        return [item for item in list_all_pages(fetch) if isinstance(item, dict)]

    def get_mod_by_source(self, source: str, source_id: int) -> Optional[Dict[str, Any]]:
        response = self.request(
            "get",
            "/mods",
            params={
                "page_size": 1,
                "page": 0,
                "sources": [source],
                "source_ids": [source_id],
                "include": ["dates"],
            },
        )
        if not self.is_success(response):
            return None
        payload = response.json()
        for item in _response_items(payload):
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
        size = _clamp_page_size(max(page_size, len(source_ids)))

        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
                "get",
                "/mods",
                params={
                    "page_size": size,
                    "page": page,
                    "sources": [source],
                    "source_ids": source_ids,
                    "include": ["dates"],
                },
            )
            if not self.is_success(response):
                return {"items": []}
            return response.json()

        return [item for item in list_all_pages(fetch) if isinstance(item, dict)]

    def find_mod_by_source(self, source: str, source_id: int) -> Optional[int]:
        mod = self.get_mod_by_source(source, source_id)
        if mod is None:
            return None
        mod_id = mod.get("id")
        if mod_id is None:
            return None
        try:
            return int(mod_id)
        except (TypeError, ValueError):
            return None

    def list_games_by_source(self, app_id: int, page_size: int) -> List[Dict[str, Any]]:
        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
                "get",
                "/games",
                params={
                    "page_size": _clamp_page_size(page_size),
                    "page": page,
                    "sources": ["steam"],
                    "source_ids": [app_id],
                },
            )
            response.raise_for_status()
            return response.json()

        return [item for item in list_all_pages(fetch) if isinstance(item, dict)]

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
            "/games",
            json={
                "name": name,
                "short_description": short_desc,
                "description": desc,
                "type": "game",
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
            "patch",
            f"/games/{game_id}",
            json={
                "source": source,
                "source_id": source_id,
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
                "include": [
                    "short_description",
                    "description",
                    "dates",
                    "game",
                ],
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

    @staticmethod
    def _json_payload(response: requests.Response) -> Dict[str, Any] | None:
        try:
            payload = response.json()
        except ValueError:
            return None
        if isinstance(payload, dict):
            return payload
        return None

    @staticmethod
    def _parse_transfer_token_payload(token: str | None) -> Dict[str, Any] | None:
        raw = str(token or "").strip()
        if not raw:
            return None
        parts = raw.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1].replace("-", "+").replace("_", "/")
        padding = len(payload) % 4
        if padding:
            payload += "=" * (4 - padding)
        try:
            decoded = base64.b64decode(payload)
            parsed = json.loads(decoded.decode("utf-8"))
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            return None
        if isinstance(parsed, dict):
            return parsed
        return None

    @staticmethod
    def _job_id_from_transfer_token(transfer_url: str) -> str | None:
        token = urlparse(transfer_url).query
        if token:
            token_value = dict(parse_qsl(token, keep_blank_values=True)).get("token")
        else:
            token_value = None
        payload = OWClient._parse_transfer_token_payload(token_value)
        if not isinstance(payload, dict):
            return None
        job_id = payload.get("job_id")
        if job_id is None:
            return None
        rendered = str(job_id).strip()
        return rendered or None

    @staticmethod
    def _derive_transfer_ws_url(transfer_url: str, payload: Dict[str, Any] | None) -> str | None:
        if payload:
            ws_url = payload.get("ws_url")
            if isinstance(ws_url, str) and ws_url.strip():
                return ws_url.strip()
        parsed_upload = urlparse(transfer_url)
        token = dict(parse_qsl(parsed_upload.query, keep_blank_values=True)).get("token")
        if not token:
            return None
        job_id = None
        if payload:
            payload_job_id = payload.get("job_id")
            if payload_job_id is not None:
                job_id = str(payload_job_id).strip() or None
        if not job_id:
            job_id = OWClient._job_id_from_transfer_token(transfer_url)
        if not job_id:
            return None
        ws_scheme = "wss" if parsed_upload.scheme == "https" else "ws"
        ws_query = urlencode({"token": token})
        return urlunparse(
            (
                ws_scheme,
                parsed_upload.netloc,
                f"/transfer/ws/{job_id}",
                "",
                ws_query,
                "",
            )
        )

    @staticmethod
    def _normalize_ws_url(ws_url: str | None) -> str | None:
        raw = str(ws_url or "").strip()
        if not raw:
            return None
        if raw.startswith("http://"):
            return "ws://" + raw[len("http://") :]
        if raw.startswith("https://"):
            return "wss://" + raw[len("https://") :]
        return raw

    def _transfer_from_init(self, response: requests.Response) -> StorageTransfer | None:
        redirect_url = self._redirect_location(response)
        payload = self._json_payload(response)
        transfer_url = redirect_url
        if not transfer_url and payload:
            candidate = payload.get("transfer_url")
            if isinstance(candidate, str) and candidate.strip():
                transfer_url = candidate.strip()
        if not transfer_url:
            return None
        ws_url = self._normalize_ws_url(self._derive_transfer_ws_url(transfer_url, payload))
        return StorageTransfer(transfer_url=transfer_url, ws_url=ws_url)

    def _upload_ws_idle_timeout(self) -> float:
        return max(
            _UPLOAD_WS_IDLE_TIMEOUT_MIN,
            float(self.timeout) * _UPLOAD_WS_IDLE_TIMEOUT_FACTOR,
        )

    @staticmethod
    def _storage_progress_update(payload: Dict[str, Any]) -> StorageProgressUpdate:
        stage = str(payload.get("stage") or "").strip().lower()

        explicit_percent = payload.get("percent")
        try:
            percent_value = int(explicit_percent) if explicit_percent is not None else None
        except (TypeError, ValueError):
            percent_value = None
        if percent_value is not None:
            percent_value = max(0, min(100, percent_value))

        total = payload.get("total")
        sent = payload.get("bytes")
        try:
            total_value = int(total) if total is not None else None
        except (TypeError, ValueError):
            total_value = None
        try:
            sent_value = int(sent) if sent is not None else None
        except (TypeError, ValueError):
            sent_value = None

        if percent_value is None and total_value and total_value > 0 and sent_value is not None:
            percent_value = min(100, int((sent_value * 100) / total_value))

        return StorageProgressUpdate(
            stage=stage,
            percent=percent_value,
            sent_bytes=sent_value,
            total_bytes=total_value,
            explicit_percent=explicit_percent is not None,
        )

    async def _upload_file_to_storage_async(
        self,
        transfer: StorageTransfer,
        file_path: Path,
        file_size: int | None,
        headers: Dict[str, str],
    ) -> StorageUploadResponse:
        import aiohttp

        upload_timeout = aiohttp.ClientTimeout(
            total=None,
            connect=float(self.timeout),
            sock_connect=float(self.timeout),
            sock_read=None,
        )
        ws_idle_timeout = self._upload_ws_idle_timeout()
        last_activity = time.monotonic()
        last_stage = ""
        last_progress_percent = -1
        ws_watchdog_enabled = False
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        ws_error_future: asyncio.Future[None] = loop.create_future()

        def mark_activity() -> None:
            nonlocal last_activity
            last_activity = time.monotonic()

        async def watch_ws_progress() -> None:
            nonlocal last_stage
            nonlocal last_progress_percent
            nonlocal ws_watchdog_enabled
            ws_url = transfer.ws_url
            if not ws_url:
                return
            try:
                async with aiohttp.ClientSession(timeout=upload_timeout) as ws_session:
                    async with ws_session.ws_connect(ws_url, autoping=True, heartbeat=30) as ws:
                        logging.info("Connected to storage upload websocket for %s", file_path.name)
                        mark_activity()
                        async for message in ws:
                            if stop_event.is_set():
                                break
                            if message.type != aiohttp.WSMsgType.TEXT:
                                continue
                            try:
                                payload = json.loads(message.data)
                            except (TypeError, ValueError):
                                continue
                            if not isinstance(payload, dict):
                                continue
                            if not ws_watchdog_enabled:
                                ws_watchdog_enabled = True
                                logging.info("Storage upload watchdog armed for %s", file_path.name)
                            mark_activity()
                            event = str(payload.get("event") or "").strip().lower()
                            stage = str(payload.get("stage") or "").strip()
                            if stage and stage != last_stage:
                                last_stage = stage
                                last_progress_percent = -1
                                logging.info("Storage upload stage for %s: %s", file_path.name, stage)
                            if event == "progress":
                                progress = self._storage_progress_update(payload)
                                if progress.percent is None:
                                    continue
                                should_log = (
                                    last_progress_percent < 0
                                    or progress.percent >= last_progress_percent + 10
                                    or progress.percent == 100
                                )
                                if not should_log:
                                    continue
                                last_progress_percent = progress.percent
                                if progress.explicit_percent:
                                    logging.info(
                                        "Storage upload progress for %s: stage=%s percent=%s%%",
                                        file_path.name,
                                        progress.stage or "unknown",
                                        progress.percent,
                                    )
                                elif (
                                    progress.sent_bytes is not None
                                    and progress.total_bytes is not None
                                    and progress.total_bytes > 0
                                ):
                                    logging.info(
                                        "Storage upload progress for %s: %s%% (%s/%s bytes)",
                                        file_path.name,
                                        progress.percent,
                                        progress.sent_bytes,
                                        progress.total_bytes,
                                    )
                            elif event == "complete":
                                logging.info("Storage upload completed for %s", file_path.name)
                                return
                            elif event == "error":
                                message_text = str(payload.get("message") or "Storage websocket reported upload error")
                                if not ws_error_future.done():
                                    ws_error_future.set_exception(RuntimeError(message_text))
                                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logging.warning("Storage upload websocket is unavailable for %s: %s", file_path.name, exc)

        async def watchdog() -> None:
            if not transfer.ws_url:
                return
            while not stop_event.is_set():
                await asyncio.sleep(_UPLOAD_WATCHDOG_POLL_SECONDS)
                if not ws_watchdog_enabled:
                    continue
                idle_for = time.monotonic() - last_activity
                if idle_for <= ws_idle_timeout:
                    continue
                raise TimeoutError(
                    f"Storage upload websocket was idle for {idle_for:.1f}s "
                    f"(limit {ws_idle_timeout:.1f}s) for {file_path.name}"
                )

        async def post_upload() -> StorageUploadResponse:
            async with aiohttp.ClientSession(timeout=upload_timeout) as upload_session:
                with file_path.open("rb") as handle:
                    async with upload_session.post(
                        transfer.transfer_url,
                        data=handle,
                        headers=headers,
                        allow_redirects=False,
                    ) as response:
                        text = await response.text()
                        return StorageUploadResponse(
                            status_code=int(response.status),
                            text=text,
                            headers=dict(response.headers),
                        )

        ws_task = asyncio.create_task(watch_ws_progress())
        watchdog_task = asyncio.create_task(watchdog())
        upload_task = asyncio.create_task(post_upload())
        try:
            wait_targets: set[asyncio.Future[Any] | asyncio.Task[Any]] = {upload_task}
            if transfer.ws_url:
                wait_targets.add(watchdog_task)
                wait_targets.add(ws_error_future)
            done, pending = await asyncio.wait(wait_targets, return_when=asyncio.FIRST_COMPLETED)
            if upload_task in done:
                return await upload_task
            if ws_error_future in done:
                upload_task.cancel()
                await asyncio.gather(upload_task, return_exceptions=True)
                await ws_error_future
            if watchdog_task in done:
                upload_task.cancel()
                await asyncio.gather(upload_task, return_exceptions=True)
                await watchdog_task
            return await upload_task
        finally:
            stop_event.set()
            ws_task.cancel()
            watchdog_task.cancel()
            await asyncio.gather(ws_task, watchdog_task, return_exceptions=True)

    def _upload_file_to_storage(
        self,
        redirect_response: requests.Response,
        file_path,
    ) -> StorageUploadResponse:
        transfer = self._transfer_from_init(redirect_response)
        if not transfer:
            raise RuntimeError("Storage init does not contain transfer URL")
        resolved_path = Path(file_path)
        upload_url = transfer.transfer_url
        parsed_upload = urlparse(upload_url)
        file_size: int | None = None
        try:
            file_size = int(resolved_path.stat().st_size)
        except (AttributeError, OSError, TypeError, ValueError):
            pass
        query = dict(parse_qsl(parsed_upload.query, keep_blank_values=True))
        query.setdefault("filename", resolved_path.name)
        if file_size is not None and file_size >= 0:
            query.setdefault("size", str(file_size))
        if query:
            upload_url = urlunparse(parsed_upload._replace(query=urlencode(query)))
            parsed_upload = urlparse(upload_url)
            transfer = StorageTransfer(transfer_url=upload_url, ws_url=transfer.ws_url)

        with start_span(
            "ow.upload_file_to_storage",
            {
                "http.request.method": "POST",
                "http.route": parsed_upload.path or "/",
                "ow.upload.host": parsed_upload.netloc or parsed_upload.hostname or "",
                "ow.upload.file_name": resolved_path.name,
                "ow.upload.file_size": file_size,
                "ow.redirect.status_code": redirect_response.status_code,
                "ow.upload.ws_enabled": bool(transfer.ws_url),
            },
        ) as span:
            try:
                headers = {
                    "Content-Type": "application/octet-stream",
                    "X-File-Name": resolved_path.name,
                }
                if file_size is not None and file_size >= 0:
                    headers["X-File-Size"] = str(file_size)
                response = asyncio.run(
                    self._upload_file_to_storage_async(
                        transfer,
                        resolved_path,
                        file_size,
                        headers,
                    )
                )
            except requests.RequestException as exc:
                span.record_exception(exc)
                span.set_attribute("error.type", type(exc).__name__)
                span.set_attribute("error.message", str(exc)[:500])
                raise
            except Exception as exc:
                span.record_exception(exc)
                span.set_attribute("error.type", type(exc).__name__)
                span.set_attribute("error.message", str(exc)[:500])
                raise

            span.set_attribute("http.response.status_code", response.status_code)
            try:
                response_size = int(response.headers.get("Content-Length", ""))
            except (TypeError, ValueError):
                response_size = None
            if response_size is not None and response_size >= 0:
                span.set_attribute("http.response.body.size", response_size)
            return response

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
                "name": mod_name,
                "short_description": short_desc,
                "description": desc,
                "source": source,
                "source_id": source_id,
                "game_id": game_id,
                "public": public_mode,
                "without_author": bool(without_author),
            }
            return self.request(
                "post",
                "/mods",
                json=data,
            )

        response = send(name)
        if response.status_code in (409, 412):
            existing_id = self._find_mod_by_source_with_wait(source, source_id)
            if existing_id is not None:
                return _result(existing_id, False)
            raise RuntimeError(
                f"Failed to add mod: {response.status_code} {response.text}"
            )
        response = self._retry_mod_name(send, name, response)
        if response.status_code in (409, 412):
            existing_id = self._find_mod_by_source_with_wait(source, source_id)
            if existing_id is not None:
                return _result(existing_id, False)
            raise RuntimeError(
                f"Failed to add mod: {response.status_code} {response.text}"
            )
        if not self.is_success(response):
            raise RuntimeError(
                f"Failed to add mod: {response.status_code} {response.text}"
            )
        mod_id = self.extract_id(response)
        if mod_id is not None:
            upload_response = self.request(
                "post",
                "/uploads",
                json={
                    "kind": "mod_archive",
                    "owner_type": "mod",
                    "owner_id": mod_id,
                    "mode": "create",
                    "format": Path(file_path).suffix.lstrip(".").lower() or "zip",
                },
                allow_redirects=False,
            )
            if not self.is_success(upload_response):
                raise RuntimeError(
                    "Failed to create mod upload job: "
                    f"{upload_response.status_code} {upload_response.text}"
                )
            upload_result = self._upload_file_to_storage(upload_response, file_path)
            if not self.is_success(upload_result):
                raise RuntimeError(
                    "Failed to upload mod file: "
                    f"{upload_result.status_code} {upload_result.text}"
                )
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
        *,
        existing_id: int | None = None,
    ) -> tuple[int, bool]:
        if existing_id is None:
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

        # If add hit a source conflict, ensure the file is uploaded to the existing mod.
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
                "name": mod_name,
                "short_description": short_desc,
                "description": desc,
                "game_id": game_id,
                "public": public_mode,
            }
            if set_source:
                data["source"] = source
                data["source_id"] = source_id
            return self.request("patch", f"/mods/{mod_id}", json=data)

        response = send(name)
        response = self._retry_mod_name(send, name, response)
        if not self.is_success(response):
            raise RuntimeError(
                f"Failed to edit mod {mod_id}: {response.status_code} {response.text}"
            )
        if file_path:
            file_response = self.request(
                "post",
                "/uploads",
                json={
                    "kind": "mod_archive",
                    "owner_type": "mod",
                    "owner_id": mod_id,
                    "mode": "replace",
                    "format": Path(file_path).suffix.lstrip(".").lower() or "zip",
                },
                allow_redirects=False,
            )
            if not self.is_success(file_response):
                raise RuntimeError(
                    f"Failed to start mod file update {mod_id}: "
                    f"{file_response.status_code} {file_response.text}"
                )
            upload_response = self._upload_file_to_storage(file_response, file_path)
            if not self.is_success(upload_response):
                raise RuntimeError(
                    f"Failed to update mod file {mod_id}: "
                    f"{upload_response.status_code} {upload_response.text}"
                )

    def list_tags(self, game_id: int, page_size: int) -> List[Dict[str, Any]]:
        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
                "get",
                "/tags",
                params={
                    "game_id": game_id,
                    "page_size": _clamp_page_size(page_size),
                    "page": page,
                },
            )
            response.raise_for_status()
            return response.json()

        return [item for item in list_all_pages(fetch) if isinstance(item, dict)]

    def add_tag(self, name: str) -> int:
        response = self.request(
            "post",
            "/tags",
            json={"name": self.limits.limit_tag_name(name)},
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
            f"/games/{game_id}/tags/{tag_id}",
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
        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
                "get",
                f"/mods/{mod_id}/tags",
                params={"page_size": 50, "page": page},
            )
            if response.status_code == 404:
                return {"items": []}
            response.raise_for_status()
            return response.json()

        tag_ids: List[int] = []
        for item in list_all_pages(fetch):
            if isinstance(item, dict):
                tag_id = item.get("id") or item.get("tag_id")
            else:
                tag_id = item
            if tag_id is None:
                continue
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
        dep_ids: List[int] = []
        for item in _response_items(payload):
            if isinstance(item, dict):
                dep_id = item.get("id") or item.get("mod_id") or item.get("dependence")
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
        def fetch(page: int) -> Dict[str, Any]:
            response = self.request(
                "get",
                "/resources",
                params={
                    "owner_type": "mods",
                    "owner_id": mod_id,
                    "page_size": 50,
                    "page": page,
                },
            )
            if response.status_code == 404:
                return {"items": []}
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict):
                return payload
            if isinstance(payload, list):
                return {"items": payload, "pagination": {"total": len(payload)}}
            return {"items": []}

        results = list_all_pages(fetch)
        return [item for item in results if isinstance(item, dict)]

    def add_resource(
        self, owner_type: str, owner_id: int, res_type: str, url: str
    ) -> None:
        response = self.request(
            "post",
            "/resources",
            json={
                "owner_type": owner_type,
                "type": res_type,
                "url": url,
                "owner_id": owner_id,
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
        init_response = self.request(
            "post",
            "/uploads",
            json={
                "kind": "resource_image",
                "owner_type": "resource",
                "mode": "create",
                "resource_owner_type": owner_type,
                "resource_owner_id": owner_id,
                "resource_type": res_type,
            },
            allow_redirects=False,
        )
        if self.is_success(init_response):
            try:
                upload_response = self._upload_file_to_storage(init_response, file_path)
            except Exception as exc:
                logging.warning(
                    "Failed to start resource file upload %s to %s %s: %s",
                    file_path,
                    owner_type,
                    owner_id,
                    exc,
                )
                return False
            if self.is_success(upload_response):
                return True
            logging.warning(
                "Failed to upload resource file %s to %s %s: %s %s",
                file_path,
                owner_type,
                owner_id,
                upload_response.status_code,
                (upload_response.text or "")[:200],
            )
            return False
        logging.warning(
            "Failed to add resource file %s to %s %s: %s %s",
            file_path,
            owner_type,
            owner_id,
            init_response.status_code,
            (init_response.text or "")[:200],
        )
        return False

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
        except ValueError:
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


def list_all_pages(fetch_page: Callable[[int], Dict[str, Any]]) -> List[Any]:
    results: List[Any] = []
    page = 0
    while True:
        payload = fetch_page(page)
        page_results = _response_items(payload)
        results.extend(page_results)
        total = _response_total(payload)
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
