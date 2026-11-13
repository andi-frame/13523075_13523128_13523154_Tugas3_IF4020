"""``trust add|list|remove`` command registration and handlers."""

import argparse
import sys

from .trust import TrustKeyNotFoundError, add_trust, list_trust, remove_trust


def register_trust(subparsers) -> None:
    parser = subparsers.add_parser("trust", help="Manage the trusted public key store")
    commands = parser.add_subparsers(dest="trust_command", required=True, metavar="{add,list,remove}")

    add = commands.add_parser("add", help="Allow a public key to sign a package")
    add.add_argument("--key", required=True, help="SPKI PEM public key file")
    add.add_argument("--package", required=True, help="package name the key may sign")
    add.add_argument("--store", required=True, help="trust store JSON (created if missing)")
    add.set_defaults(handler=handle_add)

    show = commands.add_parser("list", help="List trusted keys and allowed packages")
    show.add_argument("--store", required=True, help="trust store JSON")
    show.set_defaults(handler=handle_list)

    remove = commands.add_parser("remove", help="Remove a trusted key by keyid")
    remove.add_argument("--keyid", required=True, help="public key fingerprint")
    remove.add_argument("--store", required=True, help="trust store JSON")
    remove.set_defaults(handler=handle_remove)


def _fail(exc: Exception) -> int:
    print(f"error: {exc}", file=sys.stderr)
    return 2


def handle_add(args: argparse.Namespace) -> int:
    try:
        with open(args.key, "rb") as stream:
            pem = stream.read()
        result = add_trust(args.store, pem, args.package)
    except (OSError, ValueError) as exc:
        return _fail(exc)
    entry = result.entry
    state = "added" if result.changed else "already trusted, no change"
    print(f"Trusted key ({state})")
    print(f"  keyid:     {entry.keyid}")
    print(f"  algorithm: {entry.algorithm}")
    print(f"  package:   {result.package}")
    print(f"  packages:  {', '.join(entry.packages)}")
    return 0


def handle_list(args: argparse.Namespace) -> int:
    try:
        entries = list_trust(args.store)
    except (OSError, ValueError) as exc:
        return _fail(exc)
    if not entries:
        print("No trusted keys.")
    for entry in entries:
        print(f"{entry.keyid}  {entry.algorithm}  {','.join(entry.packages)}")
    return 0


def handle_remove(args: argparse.Namespace) -> int:
    try:
        entry = remove_trust(args.store, args.keyid)
    except TrustKeyNotFoundError as exc:
        return _fail(exc)
    except (OSError, ValueError) as exc:
        return _fail(exc)
    print(f"Removed key {entry.keyid} ({entry.algorithm}; packages: {', '.join(entry.packages)})")
    return 0
