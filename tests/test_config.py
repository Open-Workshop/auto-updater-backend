import unittest
from unittest.mock import patch

from core.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_clamps_runtime_values(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "OW_POLL_INTERVAL": "0",
                "OW_HTTP_TIMEOUT": "-5",
                "OW_HTTP_RETRIES": "-1",
                "OW_HTTP_RETRY_BACKOFF": "-0.5",
                "OW_STEAM_HTTP_RETRIES": "-2",
                "OW_STEAM_HTTP_BACKOFF": "-1",
                "OW_STEAM_REQUEST_DELAY": "-0.5",
                "OW_STEAM_DELAY": "-3",
                "OW_MAX_SCREENSHOTS": "-7",
            },
            clear=False,
        ):
            cfg = load_config()

        self.assertEqual(cfg.poll_interval, 1)
        self.assertEqual(cfg.timeout, 1)
        self.assertEqual(cfg.http_retries, 0)
        self.assertEqual(cfg.http_retry_backoff, 0.0)
        self.assertEqual(cfg.steam_http_retries, 0)
        self.assertEqual(cfg.steam_http_backoff, 0.0)
        self.assertEqual(cfg.steam_request_delay, 0.0)
        self.assertEqual(cfg.steam_delay, 0.0)
        self.assertEqual(cfg.max_screenshots, 0)


if __name__ == "__main__":
    unittest.main()
