from __future__ import annotations

import logging
import re
from typing import Iterable


LOG_TAG_ALL = "all"
LOG_TAG_PARSER = "parser"
LOG_TAG_STEAM = "steam"
LOG_TAG_OW = "ow"
LOG_TAG_OTHER = "other"
KNOWN_LOG_TAGS = (
    LOG_TAG_PARSER,
    LOG_TAG_STEAM,
    LOG_TAG_OW,
    LOG_TAG_OTHER,
)
PREFERRED_LOG_TAG_ORDER = (
    LOG_TAG_STEAM,
    LOG_TAG_OW,
    LOG_TAG_PARSER,
    LOG_TAG_OTHER,
)
PREFERRED_UI_LOG_TAG_ORDER = (
    LOG_TAG_ALL,
    LOG_TAG_STEAM,
    LOG_TAG_OW,
    LOG_TAG_PARSER,
)
LOG_TAG_LABELS = {
    LOG_TAG_ALL: "All",
    LOG_TAG_STEAM: "Steam",
    LOG_TAG_OW: "OW",
    LOG_TAG_PARSER: "Parser",
    LOG_TAG_OTHER: "Other",
}
_TAGGED_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?\s+[A-Z]+\s+\[(?P<tag>[a-z0-9_-]+)\](?:\s|$)"
)


def normalize_log_tag(value: str | None) -> str:
    rendered = str(value or "").strip().lower()
    if rendered in KNOWN_LOG_TAGS:
        return rendered
    if rendered == LOG_TAG_ALL:
        return LOG_TAG_ALL
    return ""


def _default_log_tag(record: logging.LogRecord) -> str:
    path = str(getattr(record, "pathname", "") or "").replace("\\", "/")
    if "/steam/" in path:
        return LOG_TAG_STEAM
    if "/ow/" in path:
        return LOG_TAG_OW
    if "/services/parser_service.py" in path or "/sync/" in path:
        return LOG_TAG_PARSER
    return LOG_TAG_OTHER


def derive_log_tag(record: logging.LogRecord) -> str:
    explicit_tag = normalize_log_tag(getattr(record, "log_tag", ""))
    if explicit_tag and explicit_tag != LOG_TAG_ALL:
        return explicit_tag
    return _default_log_tag(record)


class TaggedFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        record.log_tag = derive_log_tag(record)
        return super().format(record)


class TaggedLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: object, kwargs: dict) -> tuple[object, dict]:
        extra = dict(kwargs.get("extra") or {})
        extra.setdefault("log_tag", self.extra["log_tag"])
        kwargs["extra"] = extra
        return msg, kwargs


def tagged_logger(tag: str) -> TaggedLoggerAdapter:
    normalized_tag = normalize_log_tag(tag)
    logger_name = normalized_tag or LOG_TAG_PARSER
    return TaggedLoggerAdapter(logging.getLogger(logger_name), {"log_tag": logger_name})


def parser_log_handler() -> logging.Handler:
    handler = logging.StreamHandler()
    handler.setFormatter(
        TaggedFormatter("%(asctime)s %(levelname)s [%(log_tag)s] %(message)s")
    )
    return handler


def extract_log_tag(line: str) -> str:
    match = _TAGGED_LINE_RE.match(str(line or ""))
    if not match:
        return ""
    return normalize_log_tag(match.group("tag"))


def available_log_tags(text: str) -> list[str]:
    seen: set[str] = set()
    for line in str(text or "").splitlines():
        tag = extract_log_tag(line)
        if tag:
            seen.add(tag)
    ordered = [tag for tag in PREFERRED_LOG_TAG_ORDER if tag in seen]
    extras = sorted(tag for tag in seen if tag not in PREFERRED_LOG_TAG_ORDER)
    return ordered + extras


def filter_log_text_by_tag(text: str, tag: str | None) -> tuple[str, list[str], str]:
    rendered_text = str(text or "")
    rendered_tag = normalize_log_tag(tag) or LOG_TAG_ALL
    tags = available_log_tags(rendered_text)
    if rendered_tag == LOG_TAG_ALL or not rendered_text:
        return rendered_text, tags, rendered_tag

    blocks: list[tuple[str, list[str]]] = []
    current_tag = LOG_TAG_OTHER
    current_lines: list[str] = []

    def flush_current() -> None:
        if current_lines:
            blocks.append((current_tag, list(current_lines)))

    for line in rendered_text.splitlines():
        line_tag = extract_log_tag(line)
        if line_tag:
            flush_current()
            current_lines = [line]
            current_tag = line_tag
            continue
        if current_lines:
            current_lines.append(line)
            continue
        current_lines = [line]
        current_tag = LOG_TAG_OTHER
    flush_current()

    filtered_lines: list[str] = []
    for block_tag, block_lines in blocks:
        if block_tag == rendered_tag:
            filtered_lines.extend(block_lines)

    filtered_text = "\n".join(filtered_lines)
    if rendered_text.endswith("\n") and filtered_text:
        filtered_text += "\n"
    return filtered_text, tags, rendered_tag


def format_log_tag_options(tags: Iterable[str]) -> list[dict[str, str]]:
    seen: set[str] = set()
    options: list[dict[str, str]] = []
    for tag in PREFERRED_UI_LOG_TAG_ORDER:
        options.append({"value": tag, "label": LOG_TAG_LABELS[tag]})
        seen.add(tag)
    for tag in tags:
        normalized = normalize_log_tag(tag)
        if not normalized or normalized in seen:
            continue
        options.append(
            {
                "value": normalized,
                "label": LOG_TAG_LABELS.get(normalized, normalized.upper()),
            }
        )
        seen.add(normalized)
    return options
