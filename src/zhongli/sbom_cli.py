"""``sbom create``, ``sbom sign`` and ``sbom verify`` registration and handlers."""

import argparse
import json
import sys

from .sbom import SbomVerificationResult, create_sbom, sign_sbom, verify_release_with_sbom


def register_sbom(subparsers) -> None:
    parser = subparsers.add_parser("sbom", help="Create, sign and verify an SBOM bound to a release artifact")
    commands = parser.add_subparsers(dest="sbom_command", required=True, metavar="SBOM_COMMAND")

    create = commands.add_parser("create", help="Write a CycloneDX 1.6 SBOM that records the artifact SHA-256")
    create.add_argument("--file", required=True, help="release artifact the SBOM describes")
    create.add_argument("--package", required=True, help="package name")
    create.add_argument("--version", required=True, help="release version")
    create.add_argument("--lock", help="uv.lock whose runtime dependencies are listed as components")
    create.add_argument("--out", required=True, help="SBOM JSON to write")
    create.set_defaults(handler=handle_create)

    sign = commands.add_parser("sign", help="Sign an SBOM as a separate artifact (same bundle format)")
    sign.add_argument("--sbom", required=True, help="SBOM JSON to sign")
    sign.add_argument("--package", required=True, help="package name; must match the SBOM")
    sign.add_argument("--version", required=True, help="release version; must match the SBOM")
    sign.add_argument("--key", required=True, help="PKCS8 PEM private key; selects the profile")
    sign.add_argument("--out", required=True, help="SBOM bundle JSON to write")
    sign.set_defaults(handler=handle_sign)

    verify = commands.add_parser(
        "verify", help="Verify the release bundle, the SBOM bundle and that the SBOM names the artifact")
    verify.add_argument("--file", required=True, help="release artifact")
    verify.add_argument("--bundle", required=True, help="release bundle JSON")
    verify.add_argument("--sbom", required=True, help="SBOM JSON")
    verify.add_argument("--sbom-bundle", required=True, dest="sbom_bundle", help="SBOM bundle JSON")
    verify.add_argument("--trust-store", required=True, dest="trust_store", help="trust store JSON")
    verify.add_argument("--package", required=True, help="expected package name")
    verify.add_argument("--version", required=True, help="expected release version")
    verify.add_argument("--json", action="store_true", help="print the result as a single JSON object on stdout")
    verify.set_defaults(handler=handle_verify)


def handle_create(args: argparse.Namespace) -> int:
    try:
        subject = create_sbom(args.file, args.package, args.version, args.out, args.lock)
    except (OSError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote {args.out} ({subject.artifact_name}, sha256={subject.artifact_sha256}, "
          f"{subject.component_count} components)")
    return 0


def handle_sign(args: argparse.Namespace) -> int:
    try:
        result = sign_sbom(args.sbom, args.package, args.version, args.key, args.out)
    except (OSError, ValueError) as exc:
        print(f"INPUT_ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"Signed {args.out} ({result.algorithm}, keyid={result.keyid})")
    return 0


def emit_sbom(result: SbomVerificationResult, as_json: bool) -> int:
    """Write ``result`` to stdout/stderr and return its exit code."""
    stage = f" ({result.stage})" if result.stage else ""
    failure = f"{result.status}{stage}: {result.message}"
    if as_json:
        sys.stdout.write(json.dumps(result.to_json()) + "\n")
        if not result.valid:
            print(failure, file=sys.stderr)
    elif result.valid:
        print(f"{result.status}: {result.message}")
        print(f"  package:  {result.artifact.package} {result.artifact.version}")
        print(f"  artifact: {result.binding['artifact_name']} sha256={result.binding['artifact_sha256']}")
        print(f"  release:  {result.artifact.algorithm} keyid={result.artifact.keyid}")
        print(f"  sbom:     {result.sbom.algorithm} keyid={result.sbom.keyid}")
    else:
        print(failure, file=sys.stderr)
    return result.exit_code


def handle_verify(args: argparse.Namespace) -> int:
    result = verify_release_with_sbom(args.file, args.bundle, args.sbom, args.sbom_bundle,
                                      args.trust_store, args.package, args.version)
    return emit_sbom(result, args.json)
