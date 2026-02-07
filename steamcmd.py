import logging
import subprocess
from pathlib import Path

from utils import ensure_dir


def download_steam_mod(
    steamcmd_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
) -> bool:
    if not steamcmd_path.exists():
        logging.error("steamcmd not found at %s", steamcmd_path)
        return False
    ensure_dir(steam_root)
    cmd = [
        str(steamcmd_path),
        "+force_install_dir",
        str(steam_root),
        "+login",
        "anonymous",
        "+workshop_download_item",
        str(app_id),
        str(workshop_id),
        "validate",
        "+quit",
    ]
    logging.info("SteamCMD download: app_id=%s workshop_id=%s", app_id, workshop_id)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if result.returncode != 0:
        logging.error(
            "SteamCMD failed for workshop %s: %s",
            workshop_id,
            result.stdout[-2000:],
        )
        return False
    return True
