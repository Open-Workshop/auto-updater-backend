import unittest
import sys
import types

steam_mod = types.ModuleType("steam.steam_mod")
steam_mod.SteamMod = object
sys.modules.setdefault("steam.steam_mod", steam_mod)

from sync.metadata import ensure_game


class _FakeApi:
    def __init__(self) -> None:
        self.list_games_calls = []
        self.add_game_calls = []
        self.edit_game_source_calls = []

    def get_game(self, game_id: int):
        return {"id": game_id, "source_id": 99}

    def list_games_by_source(self, source: str, source_id: int, page_size: int):
        self.list_games_calls.append((source, source_id, page_size))
        return []

    def add_game(self, name: str, short_desc: str, desc: str) -> int:
        self.add_game_calls.append((name, short_desc, desc))
        return 123

    def edit_game_source(self, game_id: int, source: str, source_id: int) -> None:
        self.edit_game_source_calls.append((game_id, source, source_id))


class EnsureGameTests(unittest.TestCase):
    def test_ensure_game_uses_source_specific_parameters(self) -> None:
        api = _FakeApi()
        loader_calls = []

        def load_details(source_id: int, language: str, timeout: int):
            loader_calls.append((source_id, language, timeout))
            return {
                "name": "Example Game",
                "short": "Example Short",
                "description": "Example Description",
            }

        game_id = ensure_game(
            api,
            None,
            "custom-source",
            321,
            "english",
            60,
            source_details_loader=load_details,
        )

        self.assertEqual(game_id, 123)
        self.assertEqual(api.list_games_calls, [("custom-source", 321, 50)])
        self.assertEqual(api.add_game_calls, [("Example Game", "Example Short", "Example Description")])
        self.assertEqual(api.edit_game_source_calls, [(123, "custom-source", 321)])
        self.assertEqual(loader_calls, [(321, "english", 60)])

    def test_ensure_game_returns_existing_game_id_without_loading_details(self) -> None:
        api = _FakeApi()
        loader_calls = []

        def load_details(source_id: int, language: str, timeout: int):
            loader_calls.append((source_id, language, timeout))
            return {
                "name": "Example Game",
                "short": "Example Short",
                "description": "Example Description",
            }

        self.assertEqual(
            ensure_game(
                api,
                55,
                "custom-source",
                321,
                "english",
                60,
                source_details_loader=load_details,
            ),
            55,
        )
        self.assertEqual(loader_calls, [])
        self.assertEqual(api.list_games_calls, [])
        self.assertEqual(api.add_game_calls, [])

    def test_ensure_game_allows_string_source_id_for_non_steam(self) -> None:
        api = _FakeApi()
        loader_calls = []

        def load_details(source_id: str, language: str, timeout: int):
            loader_calls.append((source_id, language, timeout))
            return {
                "name": "Factorio",
                "short": "Factorio mod portal",
                "description": "Mirror Factorio mod portal content into Open Workshop.",
            }

        game_id = ensure_game(
            api,
            None,
            "factorio",
            "factorio",
            "english",
            60,
            source_details_loader=load_details,
        )

        self.assertEqual(game_id, 123)
        self.assertEqual(api.list_games_calls, [("factorio", "factorio", 50)])
        self.assertEqual(api.add_game_calls, [("Factorio", "Factorio mod portal", "Mirror Factorio mod portal content into Open Workshop.")])
        self.assertEqual(api.edit_game_source_calls, [(123, "factorio", "factorio")])
        self.assertEqual(loader_calls, [("factorio", "english", 60)])

    def test_ensure_game_requires_explicit_loader_for_non_steam_sources(self) -> None:
        api = _FakeApi()

        with self.assertRaisesRegex(RuntimeError, "source_details_loader is required"):
            ensure_game(
                api,
                None,
                "custom-source",
                321,
                "english",
                60,
            )


if __name__ == "__main__":
    unittest.main()
