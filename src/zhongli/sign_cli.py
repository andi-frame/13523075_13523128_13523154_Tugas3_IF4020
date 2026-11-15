"""``sign`` command registration and handler."""

import argparse
import sys

from .signing import sign


def register_sign(subparsers) -> None:
    parser = subparsers.add_parser("sign", help="Sign an artifact and write a release bundle")
    parser.add_argument("--file", required=True, help="artifact to sign")
    parser.add_argument("--package", required=True, help="package name")
    parser.add_argument("--version", required=True, help="release version")
    parser.add_argument("--key", required=True, help="PKCS8 PEM private key; selects the profile")
    parser.add_argument("--out", required=True, help="bundle JSON to write")
    parser.set_defaults(handler=handle_sign)


def handle_sign(args: argparse.Namespace) -> int:
    try:
        result = sign(args.file, args.package, args.version, args.key, args.out)
    except (OSError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Signed {args.out} ({result.algorithm}, keyid={result.keyid})")
    return 0
