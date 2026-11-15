"""``verify`` command registration and handler."""

import argparse
import json
import sys

from .verification import VerificationResult, verify


def register_verify(subparsers) -> None:
    parser = subparsers.add_parser("verify", help="Verify an artifact against a bundle and trust store")
    parser.add_argument("--file", required=True, help="artifact to check")
    parser.add_argument("--bundle", required=True, help="bundle JSON produced by sign")
    parser.add_argument("--trust-store", required=True, dest="trust_store", help="trust store JSON")
    parser.add_argument("--package", required=True, help="expected package name")
    parser.add_argument("--version", required=True, help="expected release version")
    parser.add_argument("--json", action="store_true",
                        help="print the result as a single JSON object on stdout")
    parser.set_defaults(handler=handle_verify)


def emit(result: VerificationResult, as_json: bool) -> int:
    """Write ``result`` to stdout/stderr and return its exit code."""
    if as_json:
        sys.stdout.write(json.dumps(result.to_json()) + "\n")
        if not result.valid:
            print(f"{result.status}: {result.message}", file=sys.stderr)
    elif result.valid:
        print(f"{result.status}: {result.message}")
        print(f"  package:   {result.package} {result.version}")
        print(f"  algorithm: {result.algorithm}")
        print(f"  keyid:     {result.keyid}")
    else:
        print(f"{result.status}: {result.message}", file=sys.stderr)
    return result.exit_code


def handle_verify(args: argparse.Namespace) -> int:
    result = verify(args.file, args.bundle, args.trust_store, args.package, args.version)
    return emit(result, args.json)
