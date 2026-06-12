from __future__ import annotations

import argparse
import sys
from typing import IO, Optional

from leakhound.engine import Scanner
from leakhound.detectors.regex_detector import RegexDetector
from leakhound.detectors.entropy_detector import EntropyDetector
from leakhound.models import Finding
from leakhound.reporters.console import ConsoleReporter
from leakhound.reporters.json_reporter import JSONReporter
from leakhound.reporters.sarif import SARIFReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakhound",
        description="Scan a file or directory for leaked secrets.",
    )
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--format", choices=["console", "json", "sarif"],
                        default="console", help="output format (default: console)")
    parser.add_argument("-o", "--output",
                        help="write machine output (json/sarif) to a file instead of stdout")
    parser.add_argument("--no-entropy", action="store_true",
                        help="disable the entropy detector (regex only)")
    parser.add_argument("--entropy-threshold", type=float, default=4.5,
                        help="entropy threshold (default: 4.5)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored output")
    return parser


def _machine_reporter(fmt: str, stream: IO[str]):
    return JSONReporter(stream=stream) if fmt == "json" else SARIFReporter(stream=stream)


def _emit(args: argparse.Namespace, findings: list[Finding]) -> None:
    if args.format == "console":
        ConsoleReporter(use_color=not args.no_color).report(findings)
        return
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            _machine_reporter(args.format, fh).report(findings)
    else:
        _machine_reporter(args.format, sys.stdout).report(findings)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    detectors = [RegexDetector()]
    if not args.no_entropy:
        detectors.append(EntropyDetector(threshold=args.entropy_threshold))

    findings = Scanner(detectors).scan_path(args.path)
    _emit(args, findings)

    # Non-zero exit when secrets are found — this is what lets CI fail a build.
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())