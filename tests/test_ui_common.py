import unittest

from ui.ui_common import _validate_float_min, _validate_int_min


class UICommonValidationTests(unittest.TestCase):
    def test_validate_int_min_rejects_small_values(self) -> None:
        self.assertEqual(
            _validate_int_min("0", minimum=1, label="Poll interval"),
            "Poll interval must be at least 1",
        )
        self.assertEqual(
            _validate_int_min("-1", minimum=0, label="HTTP retries"),
            "HTTP retries must be zero or greater",
        )

    def test_validate_float_min_rejects_small_values(self) -> None:
        self.assertEqual(
            _validate_float_min("-0.5", minimum=0.0, label="Steam request delay"),
            "Steam request delay must be zero or greater",
        )

    def test_validate_numeric_min_accepts_valid_values(self) -> None:
        self.assertIsNone(_validate_int_min("1", minimum=1, label="Poll interval"))
        self.assertIsNone(_validate_float_min("0", minimum=0.0, label="Steam request delay"))


if __name__ == "__main__":
    unittest.main()
