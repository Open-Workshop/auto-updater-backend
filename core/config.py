from dataclasses import dataclass
import os
import re

from core.instance_schema import load_sync_config_from_env

DEFAULT_DEPOTDOWNLOADER_PATH = "/opt/depotdownloader/DepotDownloader"
DEFAULT_STEAM_PROXY_POOL = ""
DEFAULT_STEAM_PROXY_SCOPE = "mod_pages"  # all / mod_pages / none

def parse_int(value: str | None, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_list(value: str | None) -> list[str]:
    if not value:
        return []
    parts = re.split(r"[,\s]+", value.strip())
    return [part for part in (p.strip() for p in parts) if part]


def parse_proxy_scope(value: str | None, default: str) -> str:
    if not value:
        return default
    normalized = value.strip().lower()
    if normalized in {"all", "steam", "full"}:
        return "all"
    if normalized in {"mod_pages", "modpages", "pages", "mods", "mod"}:
        return "mod_pages"
    if normalized in {"none", "off", "disabled", "0", "false"}:
        return "none"
    return default


@dataclass
class Config:
    api_base: str
    login_name: str
    password: str
    steam_app_id: int
    game_id: int
    mirror_root: str
    steam_root: str
    page_size: int
    poll_interval: int
    timeout: int
    http_retries: int
    http_retry_backoff: float
    run_once: bool
    log_level: str
    log_steam_requests: bool
    steam_http_retries: int
    steam_http_backoff: float
    steam_request_delay: float
    steam_proxy_pool: list[str]
    steam_proxy_scope: str
    steam_max_pages: int
    steam_start_page: int
    steam_max_items: int
    steam_delay: float
    max_screenshots: int
    depotdownloader_path: str
    upload_resource_files: bool
    scrape_preview_images: bool
    scrape_required_items: bool
    force_required_item_id: str | None
    public_mode: int
    without_author: bool
    sync_tags: bool
    prune_tags: bool
    sync_dependencies: bool
    prune_dependencies: bool
    sync_resources: bool
    prune_resources: bool
    language: str
    steamcmd_runner_url: str
    admin_host: str
    admin_port: int
    instance_name: str
    instance_namespace: str


def load_config() -> Config:
    sync_cfg = load_sync_config_from_env(os.environ)
    api_base = str(sync_cfg["api_base"])
    login_name = os.environ.get("OW_LOGIN", "")
    password = os.environ.get("OW_PASSWORD", "")

    steam_app_id = parse_int(os.environ.get("OW_STEAM_APP_ID"), 0)
    if steam_app_id <= 0:
        steam_app_id = parse_int(os.environ.get("STEAM_APP_ID"), 0)

    game_id = parse_int(os.environ.get("OW_GAME_ID"), 0)

    mirror_root = os.environ.get("OW_MIRROR_DIR", "/data/mirror")
    steam_root = os.environ.get("STEAM_ROOT", f"{mirror_root}/steam")
    page_size = int(sync_cfg["page_size"])
    poll_interval = int(sync_cfg["poll_interval"])
    timeout = int(sync_cfg["timeout"])
    http_retries = int(sync_cfg["http_retries"])
    http_retry_backoff = float(sync_cfg["http_retry_backoff"])
    run_once = bool(sync_cfg["run_once"])
    log_level = str(sync_cfg["log_level"])
    log_steam_requests = bool(sync_cfg["log_steam_requests"])
    steam_http_retries = int(sync_cfg["steam_http_retries"])
    steam_http_backoff = float(sync_cfg["steam_http_backoff"])
    steam_request_delay = float(sync_cfg["steam_request_delay"])
    steam_proxy_pool = parse_list(
        os.environ.get("OW_STEAM_PROXY_POOL", DEFAULT_STEAM_PROXY_POOL)
    )
    steam_proxy_scope = parse_proxy_scope(
        os.environ.get("OW_STEAM_PROXY_SCOPE"), DEFAULT_STEAM_PROXY_SCOPE
    )

    steam_max_pages = int(sync_cfg["steam_max_pages"])
    steam_start_page = int(sync_cfg["steam_start_page"])
    steam_max_items = int(sync_cfg["steam_max_items"])
    steam_delay = float(sync_cfg["steam_delay"])
    max_screenshots = int(sync_cfg["max_screenshots"])
    depotdownloader_path = os.environ.get("DEPOTDOWNLOADER_PATH", DEFAULT_DEPOTDOWNLOADER_PATH)
    upload_resource_files = bool(sync_cfg["upload_resource_files"])
    scrape_preview_images = bool(sync_cfg["scrape_preview_images"])
    scrape_required_items = bool(sync_cfg["scrape_required_items"])
    force_required_item_id = str(sync_cfg["force_required_item_id"]) or None
    public_mode = int(sync_cfg["public_mode"])
    without_author = bool(sync_cfg["without_author"])

    sync_tags = bool(sync_cfg["sync_tags"])
    prune_tags = bool(sync_cfg["prune_tags"])
    sync_dependencies = bool(sync_cfg["sync_dependencies"])
    prune_dependencies = bool(sync_cfg["prune_dependencies"])
    sync_resources = bool(sync_cfg["sync_resources"])
    prune_resources = bool(sync_cfg["prune_resources"])
    language = os.environ.get("STEAM_LANGUAGE", "english")
    steamcmd_runner_url = os.environ.get("OW_STEAMCMD_RUNNER_URL", "").strip()
    admin_host = os.environ.get("OW_ADMIN_HOST", "0.0.0.0").strip() or "0.0.0.0"
    admin_port = parse_int(os.environ.get("OW_ADMIN_PORT"), 8080)
    instance_name = os.environ.get("OW_INSTANCE_NAME", "").strip()
    instance_namespace = os.environ.get("OW_INSTANCE_NAMESPACE", "").strip()

    return Config(
        api_base=api_base,
        login_name=login_name,
        password=password,
        steam_app_id=steam_app_id,
        game_id=game_id,
        mirror_root=mirror_root,
        steam_root=steam_root,
        page_size=page_size,
        poll_interval=poll_interval,
        timeout=timeout,
        http_retries=http_retries,
        http_retry_backoff=http_retry_backoff,
        run_once=run_once,
        log_level=log_level,
        log_steam_requests=log_steam_requests,
        steam_http_retries=steam_http_retries,
        steam_http_backoff=steam_http_backoff,
        steam_request_delay=steam_request_delay,
        steam_proxy_pool=steam_proxy_pool,
        steam_proxy_scope=steam_proxy_scope,
        steam_max_pages=steam_max_pages,
        steam_start_page=steam_start_page,
        steam_max_items=steam_max_items,
        steam_delay=steam_delay,
        max_screenshots=max_screenshots,
        depotdownloader_path=depotdownloader_path,
        upload_resource_files=upload_resource_files,
        scrape_preview_images=scrape_preview_images,
        scrape_required_items=scrape_required_items,
        force_required_item_id=force_required_item_id,
        public_mode=public_mode,
        without_author=without_author,
        sync_tags=sync_tags,
        prune_tags=prune_tags,
        sync_dependencies=sync_dependencies,
        prune_dependencies=prune_dependencies,
        sync_resources=sync_resources,
        prune_resources=prune_resources,
        language=language,
        steamcmd_runner_url=steamcmd_runner_url,
        admin_host=admin_host,
        admin_port=admin_port,
        instance_name=instance_name,
        instance_namespace=instance_namespace,
    )
