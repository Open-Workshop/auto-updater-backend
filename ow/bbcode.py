from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from dataclasses import dataclass
from typing import Iterable, Optional

_TAG_RE = re.compile(r"\[(/?)([a-zA-Z0-9]+)(?:=([^\]]+))?\]")
_URL_RE = re.compile(r"(https?://[^\s<>'\"]+)")
_MD_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*\S)?\s*$")
_MD_HR_RE = re.compile(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$")
_MD_BULLET_RE = re.compile(r"^\s*[-*+]\s+(.*\S)?\s*$")
_MD_ORDERED_RE = re.compile(r"^\s*\d+[.)]\s+(.*\S)?\s*$")
_MD_BLOCKQUOTE_RE = re.compile(r"^\s*>\s?(.*)$")
_MD_FENCE_RE = re.compile(r"^\s*(```+|~~~+)\s*$")
_MD_IMAGE_RE = re.compile(r"!\[([^\]]*)\]\(([^)]+)\)")
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
_MD_CODE_RE = re.compile(r"`([^`]+)`")

_ALLOWED_TAGS = {
    "b",
    "i",
    "u",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "list",
    "*",
    "url",
    "img",
    "hr",
    "br",
}


@dataclass
class _Frame:
    tag: Optional[str]
    param: Optional[str]
    content: list[str]
    list_item_open: bool = False


class BBCodeConverter:
    def __init__(self, *, auto_link: bool = True, preserve_newlines: bool = True) -> None:
        self.auto_link = auto_link
        self.preserve_newlines = preserve_newlines

    def to_html(self, text: str) -> str:
        tokens = list(_tokenize(text))
        stack: list[_Frame] = [_Frame(tag=None, param=None, content=[])]

        for token in tokens:
            if token[0] == "text":
                stack[-1].content.append(self._render_text(token[1]))
                continue
            _, is_close, name, param, raw = token
            name = name.lower()
            if name not in _ALLOWED_TAGS:
                stack[-1].content.append(html.escape(raw))
                continue

            if is_close:
                if not self._close_tag(stack, name):
                    stack[-1].content.append(html.escape(raw))
                continue

            if name in {"hr", "br"}:
                stack[-1].content.append(f"<{name} />")
                continue

            if name == "*":
                if stack[-1].tag == "list":
                    if stack[-1].list_item_open:
                        stack[-1].content.append("</li>")
                    stack[-1].content.append("<li>")
                    stack[-1].list_item_open = True
                else:
                    stack[-1].content.append(html.escape(raw))
                continue

            stack.append(_Frame(tag=name, param=param, content=[]))

        while len(stack) > 1:
            self._close_tag(stack, stack[-1].tag or "")

        return "".join(stack[0].content)

    def to_text(self, text: str) -> str:
        html_text = self.to_html(text)
        plain = _strip_html(html_text)
        return plain.strip()

    def _render_text(self, value: str) -> str:
        if not value:
            return ""
        parts: list[str] = []
        last = 0
        if self.auto_link:
            for match in _URL_RE.finditer(value):
                if match.start() > last:
                    parts.append(html.escape(value[last:match.start()]))
                url = match.group(1)
                safe_url = html.escape(url, quote=True)
                parts.append(f'<a href="{safe_url}">{html.escape(url)}</a>')
                last = match.end()
        if last < len(value):
            parts.append(html.escape(value[last:]))
        rendered = "".join(parts)
        if self.preserve_newlines:
            rendered = rendered.replace("\n", "<br>\n")
        return rendered

    def _close_tag(self, stack: list[_Frame], name: str) -> bool:
        if len(stack) <= 1:
            return False
        top = stack[-1]
        if top.tag != name:
            return False

        stack.pop()
        content = "".join(top.content)

        if name == "list":
            if top.list_item_open:
                content += "</li>"
            stack[-1].content.append(f"<ul>{content}</ul>")
            return True

        if name == "img":
            src = _strip_html(content).strip()
            if src:
                safe_src = html.escape(src, quote=True)
                stack[-1].content.append(f'<img src="{safe_src}" />')
            return True

        if name == "url":
            text_content = content
            href = top.param or _strip_html(text_content).strip()
            if not href:
                stack[-1].content.append(text_content)
                return True
            safe_href = html.escape(href, quote=True)
            stack[-1].content.append(f'<a href="{safe_href}">{text_content}</a>')
            return True

        stack[-1].content.append(f"<{name}>{content}</{name}>")
        return True


def bbcode_to_html(text: str) -> str:
    return BBCodeConverter().to_html(text)


def bbcode_to_text(text: str) -> str:
    return BBCodeConverter().to_text(text)


class HTMLToBBCode(HTMLParser):
    def __init__(self, *, auto_link: bool = True) -> None:
        super().__init__(convert_charrefs=False)
        self.auto_link = auto_link
        self.parts: list[str] = []
        self.stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        name = tag.lower()
        attrs_dict = {key.lower(): value for key, value in attrs}

        if name in {"b", "strong"}:
            self.parts.append("[b]")
            self.stack.append("b")
            return
        if name in {"i", "em"}:
            self.parts.append("[i]")
            self.stack.append("i")
            return
        if name == "u":
            self.parts.append("[u]")
            self.stack.append("u")
            return
        if name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.parts.append(f"[{name}]")
            self.stack.append(name)
            return
        if name == "br":
            self.parts.append("\n")
            return
        if name == "hr":
            self.parts.append("[hr]")
            return
        if name in {"p", "div"}:
            self._ensure_block_spacing()
            self.stack.append(name)
            return
        if name in {"ul", "ol"}:
            self.parts.append("[list]\n")
            self.stack.append("list")
            return
        if name == "li":
            if self.parts and not self.parts[-1].endswith("\n"):
                self.parts.append("\n")
            self.parts.append("[*] ")
            self.stack.append("li")
            return
        if name == "a":
            href = attrs_dict.get("href") or ""
            if href:
                self.parts.append(f"[url={href}]")
                self.stack.append("url")
            else:
                self.parts.append("[url]")
                self.stack.append("url")
            return
        if name == "img":
            src = attrs_dict.get("src") or ""
            if src:
                self.parts.append(f"[img]{src}[/img]")
            return

    def handle_endtag(self, tag: str) -> None:
        name = tag.lower()
        if name in {"b", "strong"}:
            self._close_tag("b", "[/b]")
            return
        if name in {"i", "em"}:
            self._close_tag("i", "[/i]")
            return
        if name == "u":
            self._close_tag("u", "[/u]")
            return
        if name in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._close_tag(name, f"[/{name}]\n")
            return
        if name in {"p", "div"}:
            self._close_tag(name, "\n\n")
            return
        if name in {"ul", "ol"}:
            self._close_tag("list", "\n[/list]\n")
            return
        if name == "li":
            self._close_tag("li", "\n")
            return
        if name == "a":
            self._close_tag("url", "[/url]")
            return

    def handle_data(self, data: str) -> None:
        if not data:
            return
        text = html.unescape(data).replace("\xa0", " ")
        if not self.auto_link or "url" in self.stack:
            self.parts.append(text)
            return
        last = 0
        for match in _URL_RE.finditer(text):
            if match.start() > last:
                self.parts.append(text[last:match.start()])
            url = match.group(1)
            self.parts.append(f"[url]{url}[/url]")
            last = match.end()
        if last < len(text):
            self.parts.append(text[last:])

    def handle_entityref(self, name: str) -> None:
        self.parts.append(html.unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        self.parts.append(html.unescape(f"&#{name};"))

    def get_value(self) -> str:
        value = "".join(self.parts)
        value = value.replace("\r\n", "\n").replace("\r", "\n")
        value = re.sub(r"\n{3,}", "\n\n", value)
        return value.strip()

    def _close_tag(self, tag: str, closing: str) -> None:
        if tag in self.stack:
            while self.stack:
                current = self.stack.pop()
                if current == tag:
                    self.parts.append(closing)
                    break

    def _ensure_block_spacing(self) -> None:
        if not self.parts:
            return
        if not self.parts[-1].endswith("\n"):
            self.parts.append("\n\n")


def html_to_bbcode(text: str) -> str:
    parser = HTMLToBBCode()
    parser.feed(text or "")
    return parser.get_value()


class MarkdownToBBCode:
    def __init__(self, *, auto_link: bool = True) -> None:
        self.auto_link = auto_link

    def to_bbcode(self, text: str) -> str:
        lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        parts: list[str] = []
        in_list = False
        in_fence = False
        fence_marker = ""

        for raw_line in lines:
            line = raw_line.rstrip()
            stripped = line.strip()

            if in_fence:
                if stripped.startswith(fence_marker):
                    parts.append(fence_marker)
                    parts.append("\n")
                    in_fence = False
                    fence_marker = ""
                else:
                    parts.append(raw_line)
                    parts.append("\n")
                continue

            if not stripped:
                if in_list:
                    parts.append("\n[/list]\n")
                    in_list = False
                else:
                    parts.append("\n")
                continue

            fence_match = _MD_FENCE_RE.match(stripped)
            if fence_match:
                if in_list:
                    parts.append("\n[/list]\n")
                    in_list = False
                in_fence = True
                fence_marker = fence_match.group(1)
                parts.append("```")
                parts.append("\n")
                continue

            heading_match = _MD_HEADING_RE.match(stripped)
            if heading_match:
                if in_list:
                    parts.append("\n[/list]\n")
                    in_list = False
                level = len(heading_match.group(1))
                heading_text = (heading_match.group(2) or "").rstrip()
                heading_text = re.sub(r"\s+#+\s*$", "", heading_text).strip()
                parts.append(f"[h{level}]{self._render_inline(heading_text)}[/h{level}]\n")
                continue

            if _MD_HR_RE.match(stripped):
                if in_list:
                    parts.append("\n[/list]\n")
                    in_list = False
                parts.append("[hr]\n")
                continue

            bullet_match = _MD_BULLET_RE.match(raw_line)
            ordered_match = _MD_ORDERED_RE.match(raw_line)
            if bullet_match or ordered_match:
                if not in_list:
                    parts.append("[list]\n")
                    in_list = True
                item_text = (bullet_match or ordered_match).group(1) or ""
                parts.append("[*] ")
                parts.append(self._render_inline(item_text.strip()))
                parts.append("\n")
                continue

            quote_match = _MD_BLOCKQUOTE_RE.match(raw_line)
            if quote_match:
                if in_list:
                    parts.append("\n[/list]\n")
                    in_list = False
                parts.append("> ")
                parts.append(self._render_inline((quote_match.group(1) or "").strip()))
                parts.append("\n")
                continue

            if in_list:
                parts.append("\n[/list]\n")
                in_list = False

            parts.append(self._render_inline(stripped))
            parts.append("\n")

        if in_list:
            parts.append("\n[/list]\n")

        rendered = "".join(parts)
        rendered = re.sub(r"\n{3,}", "\n\n", rendered)
        return rendered.strip()

    def _render_inline(self, text: str) -> str:
        if not text:
            return ""

        placeholders: list[str] = []

        def stash(value: str) -> str:
            placeholders.append(value)
            return f"@@MDPLACEHOLDER_{len(placeholders) - 1}@@"

        rendered = _MD_CODE_RE.sub(lambda match: stash(match.group(1) or ""), text)

        def replace_image(match: re.Match[str]) -> str:
            url = (match.group(2) or "").strip()
            if not url:
                return ""
            return stash(f"[img]{url}[/img]")

        rendered = _MD_IMAGE_RE.sub(replace_image, rendered)

        def replace_link(match: re.Match[str]) -> str:
            label = self._render_inline((match.group(1) or "").strip())
            href = (match.group(2) or "").strip()
            if not href:
                return label
            return stash(f"[url={href}]{label}[/url]")

        rendered = _MD_LINK_RE.sub(replace_link, rendered)
        rendered = re.sub(r"(?<!\*)\*\*\*(.+?)\*\*\*(?!\*)", r"[b][i]\1[/i][/b]", rendered, flags=re.S)
        rendered = re.sub(r"(?<!_)___(.+?)___(?!_)", r"[b][i]\1[/i][/b]", rendered, flags=re.S)
        rendered = re.sub(r"(?<!\*)\*\*(.+?)\*\*(?!\*)", r"[b]\1[/b]", rendered, flags=re.S)
        rendered = re.sub(r"(?<!_)__(.+?)__(?!_)", r"[b]\1[/b]", rendered, flags=re.S)
        rendered = re.sub(r"(?<!\w)\*(?!\s)(.+?)(?<!\s)\*(?!\w)", r"[i]\1[/i]", rendered, flags=re.S)
        rendered = re.sub(r"(?<!\w)_(?!\s)(.+?)(?<!\s)_(?!\w)", r"[i]\1[/i]", rendered, flags=re.S)
        if self.auto_link:
            rendered = _URL_RE.sub(lambda match: f"[url={match.group(1)}]{match.group(1)}[/url]", rendered)

        for index, value in enumerate(placeholders):
            rendered = rendered.replace(f"@@MDPLACEHOLDER_{index}@@", value)
        return rendered


def markdown_to_bbcode(text: str) -> str:
    return MarkdownToBBCode().to_bbcode(text)


def _tokenize(text: str) -> Iterable[tuple[str, str] | tuple[str, bool, str, str | None, str]]:
    pos = 0
    for match in _TAG_RE.finditer(text):
        if match.start() > pos:
            yield ("text", text[pos:match.start()])
        is_close = bool(match.group(1))
        name = match.group(2)
        param = match.group(3)
        raw = match.group(0)
        yield ("tag", is_close, name, param, raw)
        pos = match.end()
    if pos < len(text):
        yield ("text", text[pos:])


def _strip_html(value: str) -> str:
    if not value:
        return ""
    text = re.sub(r"<[^>]+>", "", value)
    return html.unescape(text)
