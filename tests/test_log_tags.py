import logging
import unittest

from core.log_tags import (
    TaggedFormatter,
    available_log_tags,
    filter_log_text_by_tag,
    format_log_tag_options,
)


class LogTagTests(unittest.TestCase):
    def test_available_log_tags_preserves_preferred_order(self) -> None:
        text = "\n".join(
            [
                "2026-04-09 15:00:00,000 INFO [parser] Sync pass started",
                "2026-04-09 15:00:01,000 INFO [ow] Updating OW mod 10 metadata",
                "2026-04-09 15:00:02,000 INFO [steam] Steam workshop page fetch: page=1 max_pages=1",
            ]
        )

        self.assertEqual(available_log_tags(text), ["steam", "ow", "parser"])

    def test_filter_log_text_by_tag_keeps_multiline_traceback_block(self) -> None:
        text = "\n".join(
            [
                "2026-04-09 15:00:00,000 INFO [steam] Steam batch load: items=2",
                "Traceback (most recent call last):",
                "  File \"/app/sync/syncer.py\", line 1, in _load",
                "2026-04-09 15:00:01,000 INFO [ow] Updating OW mod 10 metadata",
            ]
        )

        filtered_text, tags, selected_tag = filter_log_text_by_tag(text, "steam")

        self.assertEqual(tags, ["steam", "ow"])
        self.assertEqual(selected_tag, "steam")
        self.assertIn("Steam batch load", filtered_text)
        self.assertIn("Traceback (most recent call last):", filtered_text)
        self.assertNotIn("Updating OW mod 10 metadata", filtered_text)

    def test_filter_log_text_by_tag_falls_back_to_all_for_unknown_tag(self) -> None:
        text = "2026-04-09 15:00:00,000 INFO [parser] Sync pass started\n"

        filtered_text, tags, selected_tag = filter_log_text_by_tag(text, "missing")

        self.assertEqual(filtered_text, text)
        self.assertEqual(tags, ["parser"])
        self.assertEqual(selected_tag, "all")

    def test_filter_log_text_by_tag_keeps_known_but_absent_tag_selected(self) -> None:
        text = "2026-04-09 15:00:00,000 INFO [steam] Steam batch load: items=2\n"

        filtered_text, tags, selected_tag = filter_log_text_by_tag(text, "ow")

        self.assertEqual(filtered_text, "")
        self.assertEqual(tags, ["steam"])
        self.assertEqual(selected_tag, "ow")

    def test_format_log_tag_options_always_exposes_primary_parser_filters(self) -> None:
        options = format_log_tag_options(["steam"])

        self.assertEqual(
            options,
            [
                {"value": "all", "label": "All"},
                {"value": "steam", "label": "Steam"},
                {"value": "ow", "label": "OW"},
                {"value": "parser", "label": "Parser"},
            ],
        )

    def test_tagged_formatter_infers_tag_from_module_path(self) -> None:
        formatter = TaggedFormatter("%(asctime)s %(levelname)s [%(log_tag)s] %(message)s")
        record = logging.LogRecord(
            name="root",
            level=logging.INFO,
            pathname="/app/steam/steam_api.py",
            lineno=10,
            msg="Steam request complete",
            args=(),
            exc_info=None,
        )

        rendered = formatter.format(record)

        self.assertIn("[steam]", rendered)

    def test_tagged_formatter_respects_explicit_tag_override(self) -> None:
        formatter = TaggedFormatter("%(levelname)s [%(log_tag)s] %(message)s")
        record = logging.LogRecord(
            name="root",
            level=logging.INFO,
            pathname="/app/sync/syncer.py",
            lineno=10,
            msg="Updating OW mod 10 metadata",
            args=(),
            exc_info=None,
        )
        record.log_tag = "ow"

        rendered = formatter.format(record)

        self.assertEqual(rendered, "INFO [ow] Updating OW mod 10 metadata")


if __name__ == "__main__":
    unittest.main()
