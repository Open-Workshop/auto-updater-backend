from dataclasses import dataclass
import os
import re

DEFAULT_API_BASE = "https://api.openworkshop.miskler.ru"
DEFAULT_PAGE_SIZE = 50
DEFAULT_POLL_INTERVAL = 10
DEFAULT_TIMEOUT = 60
DEFAULT_HTTP_RETRIES = 3
DEFAULT_HTTP_RETRY_BACKOFF = 5.0
DEFAULT_STEAM_MAX_PAGES = 50
DEFAULT_STEAM_START_PAGE = 30
DEFAULT_STEAM_PAGE_SIZE = 30
DEFAULT_STEAM_DELAY = 4
DEFAULT_MAX_SCREENSHOTS = 20
DEFAULT_STEAMCMD_PATH = "/opt/steamcmd/steamcmd.sh"
DEFAULT_STEAM_HTTP_RETRIES = 2
DEFAULT_STEAM_HTTP_BACKOFF = 2.0
DEFAULT_STEAM_REQUEST_DELAY = 4
DEFAULT_STEAM_PROXY_POOL = ""
DEFAULT_LOG_LEVEL = "DEBUG"


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


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
    steam_max_pages: int
    steam_start_page: int
    steam_max_items: int
    steam_delay: float
    max_screenshots: int
    steamcmd_path: str
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


def load_config() -> Config:
    api_base = os.environ.get("OW_API_BASE", DEFAULT_API_BASE)
    login_name = os.environ.get("OW_LOGIN", "")
    password = os.environ.get("OW_PASSWORD", "")

    steam_app_id = parse_int(os.environ.get("OW_STEAM_APP_ID"), 0)
    if steam_app_id <= 0:
        steam_app_id = parse_int(os.environ.get("STEAM_APP_ID"), 0)

    game_id = parse_int(os.environ.get("OW_GAME_ID"), 0)

    mirror_root = os.environ.get("OW_MIRROR_DIR", "/data/mirror")
    steam_root = os.environ.get("STEAM_ROOT", f"{mirror_root}/steam")
    page_size = parse_int(os.environ.get("OW_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    poll_interval = parse_int(os.environ.get("OW_POLL_INTERVAL"), DEFAULT_POLL_INTERVAL)
    timeout = parse_int(os.environ.get("OW_HTTP_TIMEOUT"), DEFAULT_TIMEOUT)
    http_retries = parse_int(os.environ.get("OW_HTTP_RETRIES"), DEFAULT_HTTP_RETRIES)
    http_retry_backoff = float(
        os.environ.get("OW_HTTP_RETRY_BACKOFF", DEFAULT_HTTP_RETRY_BACKOFF)
    )
    run_once = parse_bool(os.environ.get("OW_RUN_ONCE"), False)
    log_level = os.environ.get("OW_LOG_LEVEL", DEFAULT_LOG_LEVEL)
    log_steam_requests = parse_bool(os.environ.get("OW_LOG_STEAM_REQUESTS"), False)
    steam_http_retries = parse_int(
        os.environ.get("OW_STEAM_HTTP_RETRIES"), DEFAULT_STEAM_HTTP_RETRIES
    )
    steam_http_backoff = float(
        os.environ.get("OW_STEAM_HTTP_BACKOFF", DEFAULT_STEAM_HTTP_BACKOFF)
    )
    steam_request_delay = float(
        os.environ.get("OW_STEAM_REQUEST_DELAY", DEFAULT_STEAM_REQUEST_DELAY)
    )
    steam_proxy_pool = parse_list(
        os.environ.get("OW_STEAM_PROXY_POOL", DEFAULT_STEAM_PROXY_POOL)
    )

    steam_max_pages = parse_int(os.environ.get("OW_STEAM_MAX_PAGES"), DEFAULT_STEAM_MAX_PAGES)
    steam_start_page = parse_int(
        os.environ.get("OW_STEAM_START_PAGE"), DEFAULT_STEAM_START_PAGE
    )
    steam_max_items = parse_int(os.environ.get("OW_STEAM_MAX_ITEMS"), 0)
    steam_delay = float(os.environ.get("OW_STEAM_DELAY", DEFAULT_STEAM_DELAY))
    max_screenshots = parse_int(os.environ.get("OW_MAX_SCREENSHOTS"), DEFAULT_MAX_SCREENSHOTS)
    steamcmd_path = os.environ.get("STEAMCMD_PATH", DEFAULT_STEAMCMD_PATH)
    upload_resource_files = parse_bool(os.environ.get("OW_RESOURCE_UPLOAD_FILES"), True)
    scrape_preview_images = parse_bool(os.environ.get("OW_SCRAPE_PREVIEW_IMAGES"), True)
    scrape_required_items = parse_bool(os.environ.get("OW_SCRAPE_REQUIRED_ITEMS"), True)
    force_required_item_id = os.environ.get("OW_FORCE_REQUIRED_ITEM_ID")
    public_mode = parse_int(os.environ.get("OW_MOD_PUBLIC"), 0)
    without_author = parse_bool(os.environ.get("OW_WITHOUT_AUTHOR"), False)

    sync_tags = parse_bool(os.environ.get("OW_SYNC_TAGS"), True)
    prune_tags = parse_bool(os.environ.get("OW_PRUNE_TAGS"), True)
    sync_dependencies = parse_bool(os.environ.get("OW_SYNC_DEPENDENCIES"), True)
    prune_dependencies = parse_bool(os.environ.get("OW_PRUNE_DEPENDENCIES"), True)
    sync_resources = parse_bool(os.environ.get("OW_SYNC_RESOURCES"), True)
    prune_resources = parse_bool(os.environ.get("OW_PRUNE_RESOURCES"), True)
    language = os.environ.get("STEAM_LANGUAGE", "english")

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
        steam_max_pages=steam_max_pages,
        steam_start_page=steam_start_page,
        steam_max_items=steam_max_items,
        steam_delay=steam_delay,
        max_screenshots=max_screenshots,
        steamcmd_path=steamcmd_path,
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
    )
