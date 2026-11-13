"""``keygen`` command registration and handler."""

import argparse
import sys

from .keygen import keygen
from .keys import PROFILES


def register_keygen(subparsers) -> None:
    parser = subparsers.add_parser("keygen", help="Generate a key pair for a signing profile")
    parser.add_argument("--algorithm", required=True, choices=PROFILES, help="signing profile")
    parser.add_argument("--out", required=True, metavar="PREFIX",
                        help="writes PREFIX.key.pem (PKCS8) and PREFIX.pub.pem (SPKI)")
    parser.add_argument("--force", action="store_true",
                        help="overwrite existing key files at PREFIX (never done implicitly)")
    parser.set_defaults(handler=handle_keygen)


def handle_keygen(args: argparse.Namespace) -> int:
    try:
        result = keygen(args.algorithm, args.out, overwrite_explicit=args.force)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Generated {result.algorithm} key pair")
    print(f"  private key: {result.private_key_path}")
    print(f"  public key:  {result.public_key_path}")
    print(f"  keyid:       {result.keyid}")
    return 0
