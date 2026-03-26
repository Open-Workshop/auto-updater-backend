import os
import sys
from operator_service import run_operator
from parser_service import run_parser
from runner_service import run_runner
from ui_service import run_ui


def detect_mode(argv: list[str]) -> str:
    if len(argv) > 1:
        mode = argv[1].strip().lower()
        if mode in {"parser", "runner", "operator", "ui"}:
            return mode
    explicit = os.environ.get("OW_MODE", "").strip().lower()
    if explicit in {"parser", "runner", "operator", "ui"}:
        return explicit
    return "parser"


def main() -> int:
    mode = detect_mode(sys.argv)
    if mode == "runner":
        return run_runner()
    if mode == "operator":
        return run_operator()
    if mode == "ui":
        return run_ui()
    return run_parser()


if __name__ == "__main__":
    sys.exit(main())
