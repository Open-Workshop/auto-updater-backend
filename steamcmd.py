import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from utils import ensure_dir


@dataclass(frozen=True)
class SteamDownloadResult:
    ok: bool
    reason: str | None = None
    retryable: bool = False


_ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _strip_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value)


def _extract_steamcmd_error(output: str) -> str | None:
    cleaned = _strip_ansi(output or "").replace("\r", "\n")
    specific_match = re.search(
        r"(ERROR!\s+Download item\s+\d+\s+failed\s+\([^)]+\)\.)",
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if specific_match:
        return " ".join(specific_match.group(1).split())
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "ERROR!" in line:
            return " ".join(line.split())
    return None


def _is_retryable_reason(reason: str | None, returncode: int) -> bool:
    if reason:
        normalized = reason.lower()
        if "failed (failure)" in normalized:
            return True
        if "timeout" in normalized:
            return True
    return returncode != 0


def _read_tail_lines(path: Path, max_bytes: int = 512 * 1024) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        with path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            data = fh.read().decode("utf-8", errors="ignore")
    except OSError:
        return []
    return [line.strip() for line in data.splitlines() if line.strip()]


def _collect_steam_diagnostics(workshop_id: int) -> str | None:
    wid = str(workshop_id)
    log_dir = Path.home() / "Steam" / "logs"
    workshop_lines = _read_tail_lines(log_dir / "workshop_log.txt")
    content_lines = _read_tail_lines(log_dir / "content_log.txt")
    details: list[str] = []

    if workshop_lines:
        req_indexes = [
            idx
            for idx, line in enumerate(workshop_lines)
            if f"Download item {wid} requested by app" in line
        ]
        if req_indexes:
            start = req_indexes[-1]
            window = workshop_lines[start : start + 120]
        else:
            window = workshop_lines[-160:]
        result_line = next(
            (
                line
                for line in window
                if f"Download item {wid} result :" in line
            ),
            None,
        )
        if result_line:
            details.append(result_line)
        canceled_line = next(
            (
                line
                for line in window
                if "Update canceled:" in line
            ),
            None,
        )
        if canceled_line:
            details.append(canceled_line)

    if content_lines:
        missing_file_re = re.compile(
            rf'Validation: missing file "{re.escape(wid)}\\([^"]+)"'
        )
        missing_count = 0
        missing_examples: list[str] = []
        for line in content_lines:
            match = missing_file_re.search(line)
            if not match:
                continue
            missing_count += 1
            if len(missing_examples) < 3:
                missing_examples.append(match.group(1).replace("\\", "/"))
        if missing_count:
            examples = ", ".join(missing_examples)
            details.append(
                f"Validation missing files: {missing_count} (examples: {examples})"
            )
            quick_scan = next(
                (
                    line
                    for line in reversed(content_lines)
                    if "Validation: quick scan" in line
                ),
                None,
            )
            if quick_scan:
                details.append(quick_scan)

    if not details:
        return None
    return " | ".join(details)


def download_steam_mod(
    steamcmd_path: Path,
    steam_root: Path,
    app_id: int,
    workshop_id: int,
) -> SteamDownloadResult:
    if not steamcmd_path.exists():
        logging.error("steamcmd not found at %s", steamcmd_path)
        return SteamDownloadResult(
            False,
            f"steamcmd not found at {steamcmd_path}",
            retryable=False,
        )
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
    output = result.stdout or ""
    output_tail = _strip_ansi(output[-4000:])
    parsed_error = _extract_steamcmd_error(output)
    if result.returncode != 0:
        diagnostics = _collect_steam_diagnostics(workshop_id)
        reason = parsed_error or f"steamcmd exit code {result.returncode}"
        logging.error(
            "SteamCMD failed for workshop %s: %s",
            workshop_id,
            reason,
        )
        if diagnostics:
            logging.error("SteamCMD diagnostics for workshop %s: %s", workshop_id, diagnostics)
        if output_tail:
            logging.error("SteamCMD output tail for %s:\n%s", workshop_id, output_tail)
        return SteamDownloadResult(
            False,
            reason,
            retryable=_is_retryable_reason(reason, result.returncode),
        )
    if parsed_error:
        diagnostics = _collect_steam_diagnostics(workshop_id)
        if diagnostics:
            logging.error("SteamCMD diagnostics for workshop %s: %s", workshop_id, diagnostics)
        return SteamDownloadResult(
            False,
            parsed_error,
            retryable=_is_retryable_reason(parsed_error, result.returncode),
        )
    return SteamDownloadResult(True)
