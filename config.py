from dataclasses import dataclass
import os

DEFAULT_API_BASE = "https://api.openworkshop.miskler.ru"
DEFAULT_PAGE_SIZE = 50
DEFAULT_POLL_INTERVAL = 600
DEFAULT_TIMEOUT = 60
DEFAULT_STEAM_MAX_PAGES = 50
DEFAULT_STEAM_PAGE_SIZE = 30
DEFAULT_STEAM_DELAY = 1.0
DEFAULT_MAX_SCREENSHOTS = 8
DEFAULT_STEAMCMD_PATH = "/opt/steamcmd/steamcmd.sh"


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


@dataclass
class Config:
    api_base: str
    login_name: str
    password: str
    steam_app_id: int
    game_id: int
    mirror_root: str
    steam_root: str
    state_file: str
    page_size: int
    poll_interval: int
    timeout: int
    run_once: bool
    steam_api_key: str | None
    steam_max_pages: int
    steam_max_items: int
    steam_delay: float
    max_screenshots: int
    steamcmd_path: str
    upload_resource_files: bool
    scrape_preview_images: bool
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
    state_file = os.environ.get("OW_STATE_FILE", f"{mirror_root}/state.json")
    page_size = parse_int(os.environ.get("OW_PAGE_SIZE"), DEFAULT_PAGE_SIZE)
    poll_interval = parse_int(os.environ.get("OW_POLL_INTERVAL"), DEFAULT_POLL_INTERVAL)
    timeout = parse_int(os.environ.get("OW_HTTP_TIMEOUT"), DEFAULT_TIMEOUT)
    run_once = parse_bool(os.environ.get("OW_RUN_ONCE"), False)

    steam_api_key = os.environ.get("STEAM_WEB_API_KEY")
    steam_max_pages = parse_int(os.environ.get("OW_STEAM_MAX_PAGES"), DEFAULT_STEAM_MAX_PAGES)
    steam_max_items = parse_int(os.environ.get("OW_STEAM_MAX_ITEMS"), 0)
    steam_delay = float(os.environ.get("OW_STEAM_DELAY", DEFAULT_STEAM_DELAY))
    max_screenshots = parse_int(os.environ.get("OW_MAX_SCREENSHOTS"), DEFAULT_MAX_SCREENSHOTS)
    steamcmd_path = os.environ.get("STEAMCMD_PATH", DEFAULT_STEAMCMD_PATH)
    upload_resource_files = parse_bool(os.environ.get("OW_RESOURCE_UPLOAD_FILES"), True)
    scrape_preview_images = parse_bool(os.environ.get("OW_SCRAPE_PREVIEW_IMAGES"), True)
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
        state_file=state_file,
        page_size=page_size,
        poll_interval=poll_interval,
        timeout=timeout,
        run_once=run_once,
        steam_api_key=steam_api_key,
        steam_max_pages=steam_max_pages,
        steam_max_items=steam_max_items,
        steam_delay=steam_delay,
        max_screenshots=max_screenshots,
        steamcmd_path=steamcmd_path,
        upload_resource_files=upload_resource_files,
        scrape_preview_images=scrape_preview_images,
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
