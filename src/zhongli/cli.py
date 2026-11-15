"""Command-line entry point: global options and subcommand registration.

Each command module registers its own parser and handler; this module only wires
them together and maps failures to exit codes. All commands are non-interactive:
missing or invalid options fail immediately with exit code 2.
"""

import argparse
from importlib.metadata import version
import sys

from .keygen_cli import register_keygen
from .sbom import SbomVerificationResult
from .sbom_cli import emit_sbom, register_sbom
from .sign_cli import register_sign
from .trust_cli import register_trust
from .verification import Status, VerificationResult
from .verify_cli import emit, register_verify

PROG = "zhongli"
USAGE_EXIT = 2


class UsageError(Exception):
    def __init__(self, parser: argparse.ArgumentParser, message: str):
        super().__init__(message)
        self.parser = parser


class _Parser(argparse.ArgumentParser):
    """Raise instead of exiting so that ``verify --json`` can report INPUT_ERROR as JSON."""

    def __init__(self, *args, **kwargs):
        # Abbreviated options such as --pack are rejected rather than guessed.
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str):
        raise UsageError(self, message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Sign software release artifacts and verify them against a trust store "
                    "(rsa-pss-sha256, ecdsa-p256-sha256, ed25519).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {version(PROG)}")
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    register_keygen(subparsers)
    register_sign(subparsers)
    register_verify(subparsers)
    register_trust(subparsers)
    register_sbom(subparsers)
    return parser


def _usage_failure(error: UsageError, argv: list[str]) -> int:
    error.parser.print_usage(sys.stderr)
    if error.parser.prog == f"{PROG} verify" and "--json" in argv:
        return emit(VerificationResult(Status.INPUT_ERROR, f"Usage error: {error}"), as_json=True)
    if error.parser.prog == f"{PROG} sbom verify" and "--json" in argv:
        unchecked = VerificationResult(Status.INPUT_ERROR, "Not checked because of a usage error")
        return emit_sbom(SbomVerificationResult(Status.INPUT_ERROR, None, f"Usage error: {error}",
                                                unchecked, unchecked), as_json=True)
    print(f"{error.parser.prog}: error: {error}", file=sys.stderr)
    return USAGE_EXIT


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        args = build_parser().parse_args(argv)
    except UsageError as error:
        return _usage_failure(error, argv)
    try:
        return args.handler(args)
    except Exception as exc:
        # Exit 1 means "verification rejected"; a crash must never look like that.
        print(f"error: unexpected failure: {exc!r}", file=sys.stderr)
        return USAGE_EXIT
