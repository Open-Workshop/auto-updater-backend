from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from string import Template


MODULE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = MODULE_DIR / "templates"
STATIC_DIR = MODULE_DIR / "static"


@lru_cache(maxsize=None)
def load_template(template_name: str) -> Template:
    return Template((TEMPLATE_DIR / template_name).read_text(encoding="utf-8"))


def render_template(template_name: str, **context: str) -> str:
    return load_template(template_name).substitute(**context)
