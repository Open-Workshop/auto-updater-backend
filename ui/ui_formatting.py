"""Formatting utilities for UI service."""
from __future__ import annotations

import logging
import re
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

_QUANTITY_RE = re.compile(r"^([+-]?(?:\d+(?:\.\d+)?|\.\d+))(Ei|Pi|Ti|Gi|Mi|Ki|E|P|T|G|M|k|m|u|n)?$")
_QUANTITY_FACTORS: dict[str, Decimal] = {
    "": Decimal("1"),
    "n": Decimal("1e-9"),
    "u": Decimal("1e-6"),
    "m": Decimal("1e-3"),
    "k": Decimal("1e3"),
    "M": Decimal("1e6"),
    "G": Decimal("1e9"),
    "T": Decimal("1e12"),
    "P": Decimal("1e15"),
    "E": Decimal("1e18"),
    "Ki": Decimal(2**10),
    "Mi": Decimal(2**20),
    "Gi": Decimal(2**30),
    "Ti": Decimal(2**40),
    "Pi": Decimal(2**50),
    "Ei": Decimal(2**60),
}


def _parse_quantity_decimal(value: Any) -> Decimal | None:
    """Parse a Kubernetes quantity string to a Decimal."""
    text = str(value or "").strip()
    if not text:
        return None
    match = _QUANTITY_RE.fullmatch(text)
    if not match:
        return None
    amount_text, suffix = match.groups()
    factor = _QUANTITY_FACTORS.get(suffix or "")
    if factor is None:
        return None
    try:
        return Decimal(amount_text) * factor
    except InvalidOperation:
        return None


def _parse_cpu_millicores(value: Any) -> int | None:
    """Parse a Kubernetes CPU quantity to millicores."""
    logging.debug("_parse_cpu_millicores: value=%r (type: %s)", value, type(value))
    parsed = _parse_quantity_decimal(value)
    if parsed is None:
        logging.debug("_parse_cpu_millicores: parsed is None")
        return None
    result = int((parsed * Decimal("1000")).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    logging.debug("_parse_cpu_millicores: result=%d", result)
    return result


def _parse_bytes(value: Any) -> int | None:
    """Parse a Kubernetes memory quantity to bytes."""
    parsed = _parse_quantity_decimal(value)
    if parsed is None:
        return None
    return int(parsed.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _int_value(value: Any) -> int | None:
    """Convert a value to int, returning None if conversion fails."""
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _sum_values(values: list[int | None]) -> int | None:
    """Sum a list of int values, ignoring None values."""
    defined = [value for value in values if value is not None]
    if not defined:
        return None
    return sum(defined)


def _format_decimal(value: float, digits: int) -> str:
    """Format a decimal value with specified digits, removing trailing zeros."""
    formatted = f"{value:.{digits}f}"
    if "." not in formatted:
        return formatted
    return formatted.rstrip("0").rstrip(".")


def _format_cpu_millicores(value: int | None) -> str:
    """Format CPU millicores as a string."""
    if value is None:
        return "n/a"
    return f"{value}m"


def _format_cpu_percent(cpu_millicores: int | None, node_capacity_millicores: int | None) -> str:
    """Format CPU usage as a percentage of node capacity."""
    logging.debug("_format_cpu_percent: cpu_millicores=%r, node_capacity_millicores=%r", cpu_millicores, node_capacity_millicores)
    if cpu_millicores is None:
        return "n/a"
    if node_capacity_millicores is None or node_capacity_millicores <= 0:
        logging.debug("_format_cpu_percent: returning millicores because node_capacity is None or <= 0")
        return f"{cpu_millicores}m"
    percent = (cpu_millicores / node_capacity_millicores) * 100
    logging.debug("_format_cpu_percent: returning percent=%s", f"{_format_decimal(percent, 1)}%")
    return f"{_format_decimal(percent, 1)}%"


def _format_bytes(value: int | None) -> str:
    """Format bytes as a human-readable string using decimal units (KB, MB, GB)."""
    if value is None:
        return "n/a"
    if value < 1024:
        return f"{value}B"
    units = [
        ("EB", 10**18),
        ("PB", 10**15),
        ("TB", 10**12),
        ("GB", 10**9),
        ("MB", 10**6),
        ("KB", 10**3),
    ]
    for suffix, factor in units:
        if value >= factor:
            amount = value / factor
            digits = 0 if amount >= 100 else 1
            return f"{_format_decimal(amount, digits)}{suffix}"
    return f"{value}B"


def _format_memory_percent(memory_bytes: int | None, node_capacity_bytes: int | None) -> str:
    """Format memory usage as bytes with percentage of node capacity."""
    logging.debug("_format_memory_percent: memory_bytes=%r, node_capacity_bytes=%r", memory_bytes, node_capacity_bytes)
    if memory_bytes is None:
        return "n/a"
    if node_capacity_bytes is None or node_capacity_bytes <= 0:
        logging.debug("_format_memory_percent: returning bytes because node_capacity is None or <= 0")
        return _format_bytes(memory_bytes)
    percent = (memory_bytes / node_capacity_bytes) * 100
    logging.debug("_format_memory_percent: returning percent=%s", f"{_format_bytes(memory_bytes)} ({_format_decimal(percent, 1)}%)")
    return f"{_format_bytes(memory_bytes)} ({_format_decimal(percent, 1)}%)"


def _format_disk_usage(
    capacity_bytes: int | None,
    used_bytes: int | None,
    requested_bytes: int | None,
) -> str:
    """Format disk capacity, usage, and requested storage as a readable string."""
    if (
        capacity_bytes is None
        and used_bytes is None
        and requested_bytes is None
    ):
        return "n/a"
    parts = []
    if capacity_bytes is not None or used_bytes is not None or requested_bytes is not None:
        parts.append(f"{_format_bytes(capacity_bytes)} cap" if capacity_bytes is not None else "n/a cap")
    if used_bytes is not None or capacity_bytes is not None or requested_bytes is not None:
        parts.append(f"{_format_bytes(used_bytes)} used" if used_bytes is not None else "n/a used")
    if requested_bytes is not None or capacity_bytes is not None or used_bytes is not None:
        parts.append(
            f"{_format_bytes(requested_bytes)} req"
            if requested_bytes is not None
            else "n/a req"
        )
    return " / ".join(parts)
