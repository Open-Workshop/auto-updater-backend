import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from factorio.factorio_mod import FactorioMod, download_factorio_mod_archive, list_factorio_mod_names


class FactorioModTests(unittest.TestCase):
    def test_list_factorio_mod_names_builds_catalog_query(self) -> None:
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "pagination": {"total": 1},
            "results": [
                {"name": "dimension-warp"},
            ],
        }
        response.raise_for_status = Mock()

        with patch("factorio.factorio_mod.requests.get", return_value=response) as get_mock:
            names = list_factorio_mod_names(0)

        self.assertEqual(names, ["dimension-warp"])
        get_mock.assert_called_once()
        _, kwargs = get_mock.call_args
        self.assertEqual(kwargs["params"]["page"], 1)
        self.assertEqual(kwargs["params"]["page_size"], 50)
        self.assertEqual(kwargs["params"]["sort"], "updated_at")
        self.assertEqual(kwargs["params"]["sort_order"], "desc")
        self.assertEqual(kwargs["params"]["version"], "2.0")
        self.assertEqual(kwargs["params"]["hide_deprecated"], "true")

    def test_factorio_mod_from_api_json_parses_live_fields(self) -> None:
        payload = {
            "title": "Dimension Warp",
            "category": "logistics",
            "summary": "Move items between surfaces.\nA remake of the great warptorio2.",
            "description": (
                "# Dimension Warp\n\n"
                "Survive on a platform warping between alternate dimensions.\n\n"
                "## Features\n\n"
                "* Works **with or without** Space Age.\n"
                "* Uses [Factorio Mod Portal](https://mods.factorio.com/).\n"
            ),
            "tags": ["logistics", "transport", "transport"],
            "source_url": "https://github.com/Kyria/dimension-warp",
            "homepage": "https://github.com/Kyria/dimension-warp",
            "thumbnail": "/dimension-warp/thumb.png",
            "images": [
                {"id": 1, "thumbnail": "/dimension-warp/preview-1.png", "url": "/dimension-warp/preview-1.png"},
                {"id": 2, "thumbnail": "/dimension-warp/preview-2.png", "url": "https://assets-mod.factorio.com/dimension-warp/preview-2.png"},
            ],
            "created_at": "2026-04-29T12:00:00Z",
            "updated_at": "2026-04-30T13:30:00Z",
            "releases": [
                {
                    "version": "0.7.2",
                    "download_url": "https://example.invalid/download",
                    "file_name": "dimension-warp_0.7.2.zip",
                    "info_json": {
                        "dependencies": [
                            "base >= 2.0.29",
                            "? space-age >= 2.0.29",
                            "(?) aai-containers",
                            "Krastorio2 >= 1.3.0",
                            "! factorissimo-2-notnotmelon",
                        ]
                    },
                }
            ],
        }

        mod = FactorioMod.from_api_json("dimension-warp", payload)

        self.assertEqual(mod.item_id, "dimension-warp")
        self.assertEqual(mod.title, "Dimension Warp")
        self.assertEqual(mod.summary, "Move items between surfaces.\nA remake of the great warptorio2.")
        self.assertEqual(mod.git_url, "https://github.com/Kyria/dimension-warp")
        self.assertEqual(
            mod.description,
            (
                "# Dimension Warp\n\n"
                "Survive on a platform warping between alternate dimensions.\n\n"
                "## Features\n\n"
                "* Works **with or without** Space Age.\n"
                "* Uses [Factorio Mod Portal](https://mods.factorio.com/)."
            ),
        )
        self.assertEqual(mod.tags, ["logistics", "transport"])
        self.assertEqual(mod.version, "0.7.2")
        self.assertEqual(mod.logo, "https://assets-mod.factorio.com/dimension-warp/thumb.png")
        self.assertEqual(
            mod.screenshots,
            [
                "https://assets-mod.factorio.com/dimension-warp/preview-1.png",
                "https://assets-mod.factorio.com/dimension-warp/preview-2.png",
            ],
        )
        self.assertEqual(mod.dependencies, ["Krastorio2"])
        self.assertEqual(
            [dep.source_id for dep in mod.dependency_items],
            ["aai-containers", "Krastorio2"],
        )
        self.assertEqual(
            [dep.optional for dep in mod.dependency_items],
            [True, False],
        )
        self.assertEqual(mod.conflicts, ["factorissimo-2-notnotmelon"])
        self.assertTrue(mod.page_ok)
        self.assertGreater(mod.created_ts, 0)
        self.assertGreater(mod.updated_ts, 0)

    def test_download_factorio_mod_archive_uses_storage_host(self) -> None:
        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "application/zip"}
        response.iter_content = Mock(return_value=[b"abc", b"def"])
        response.close = Mock()

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "dimension-warp-0.7.2.zip"
            with patch("factorio.factorio_mod.requests.get", return_value=response) as get_mock:
                result = download_factorio_mod_archive("dimension-warp", "0.7.2", target)
            self.assertEqual(result, target)
            self.assertEqual(target.read_bytes(), b"abcdef")
            get_mock.assert_called_once()
            self.assertEqual(
                get_mock.call_args.args[0],
                "https://mods-storage.re146.dev/dimension-warp/0.7.2.zip",
            )


if __name__ == "__main__":
    unittest.main()
