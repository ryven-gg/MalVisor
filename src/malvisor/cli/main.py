"""Phase 0 command line interface."""

import argparse
from pathlib import Path
import sys

from malvisor import __version__
from malvisor.cli.io import read_input, write_new_output
from malvisor.differential.compare import attach_comparison, compare
from malvisor.parsers.errors import ParseError
from malvisor.parsers.limits import Limits
from malvisor.parsers.pefile_parser import parse_pe
from malvisor.parsers.report_builder import build_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="malvisor", description="Offline static PE analysis")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="show the engine version")
    analyze = commands.add_parser("analyze", help="parse a local PE file as static bytes")
    analyze.add_argument("sample", type=Path, help="authorized local PE file")
    analyze.add_argument("--output", type=Path, help="create a new report JSON file; never overwrites")
    analyze.add_argument("--compare-parsers", action="store_true", help="opt in to optional LIEF comparison")
    analyze.add_argument("--max-input-size", type=int, default=Limits().max_input_size,
                         help="maximum file size in bytes")
    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    if args.max_input_size < 1:
        parser.error("--max-input-size must be positive")
    limits = Limits(max_input_size=args.max_input_size)
    try:
        data = read_input(args.sample, limits.max_input_size)
        primary = parse_pe(data, limits)
        report = build_report(data, primary, limits)
        if args.compare_parsers:
            from malvisor.parsers.lief_parser import parse_lief

            reference = parse_lief(data, limits)
            result = compare(primary, reference, report.evidence)
            report = attach_comparison(report, reference, result)
        serialized = report.to_json()
        if args.output is None:
            sys.stdout.write(serialized)
        else:
            write_new_output(args.output, serialized)
        return 0
    except ParseError as exc:
        print(f"ERROR {exc.code}: {exc}", file=sys.stderr)
        if exc.code in ("input_too_large", "section_limit", "directory_limit", "observation_limit",
                        "issue_limit", "field_limit", "import_descriptor_limit", "import_function_limit"):
            return 3
        if exc.code.startswith("reference_"):
            return 4
        if exc.code in ("input_io", "output_io", "output_exists", "input_changed", "invalid_input_type"):
            return 5
        return 2

