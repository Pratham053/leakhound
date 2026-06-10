from __future__ import annotations

import argparse
import sys
from typing import Optional

from leakhound.engine import Scanner
from leakhound.detectors.regex_detector import RegexDetector
from leakhound.detectors.entropy_detector import EntropyDetector
from leakhound.reporters.console import ConsoleReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakhound",
        description="Scan a file or directory for leaked secrets.",
    )
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--no-entropy", action="store_true",
                        help="disable the entropy detector (regex only)")
    parser.add_argument("--entropy-threshold", type=float, default=4.5,
                        help="entropy threshold (default: 4.5)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored output")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    detectors = [RegexDetector()]
    if not args.no_entropy:
        detectors.append(EntropyDetector(threshold=args.entropy_threshold))

    findings = Scanner(detectors).scan_path(args.path)
    ConsoleReporter(use_color=not args.no_color).report(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())