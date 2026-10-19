"""Phase 0 command line interface."""

import argparse

from malvisor import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="malvisor", description="Static PE analysis project (Phase 0 foundation)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="show the engine version")
    analyze = commands.add_parser("analyze", help="reserved for a future phase")
    analyze.add_argument("sample", help="path is accepted but never opened in Phase 0")
    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    print("Not implemented in Phase 0: no sample was opened or analyzed.")
    return 2

