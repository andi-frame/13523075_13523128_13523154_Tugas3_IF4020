"""Sign command registration, ready to attach to the shared CLI parser."""

import argparse
from importlib.metadata import version
import sys

from .signing import sign


def register_sign(subparsers) -> None:
    parser = subparsers.add_parser("sign", help="Sign an artifact and write a release bundle")
    parser.add_argument("--file", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--out", required=True)
    parser.set_defaults(handler=handle_sign)


def handle_sign(args: argparse.Namespace) -> int:
    try:
        result = sign(args.file, args.package, args.version, args.key, args.out)
    except (OSError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Signed {args.out} ({result.algorithm}, keyid={result.keyid})")
    return 0


def main() -> None:
    # Minimal entry point until the shared CLI registers all command handlers.
    parser = argparse.ArgumentParser(prog="if4020-signing")
    parser.add_argument("--version", action="version", version=version("if4020-signing"))
    register_sign(parser.add_subparsers(dest="command", required=True))
    args = parser.parse_args()
    raise SystemExit(args.handler(args))
