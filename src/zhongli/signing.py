"""Build a manifest and sign its exact bytes using an algorithm adapter."""

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile
from typing import Any, Protocol

from .artifact import read_artifact
from . import keys
from .formats import build_manifest, encode_bundle, serialize_manifest


class SigningAdapter(Protocol):
    """Subset of the algorithm adapter contract needed by the signer."""

    def load_private_key(self, pem_bytes: bytes) -> Any: ...
    def public_from_private(self, private_key: Any) -> Any: ...
    def profile_of(self, validated_key: Any) -> str: ...
    def fingerprint(self, public_key: Any) -> str: ...
    def sign_bytes(self, private_key: Any, manifest_bytes: bytes) -> bytes: ...


@dataclass(frozen=True)
class SignResult:
    """What `sign` produced: profile, keyid, the signed manifest bytes, the raw signature and the bundle path."""

    algorithm: str
    keyid: str
    manifest_bytes: bytes
    signature_bytes: bytes
    output_path: Path


def _check_output(output: Path, inputs: tuple[Path, ...]) -> None:
    for source in inputs:
        if output.resolve() == source.resolve() or (
            output.exists() and source.exists() and output.samefile(source)
        ):
            raise ValueError("Bundle output must differ from the artifact and private key")


def sign(
    artifact_path: str | Path, package: str, version: str,
    private_key_path: str | Path, output_bundle_path: str | Path,
    *, adapter: SigningAdapter = keys,
) -> SignResult:
    """Hash the artifact, build its manifest, sign the manifest bytes and write the bundle.

    The profile comes from the private key, so there is no algorithm option.
    The bundle is written to a temporary file and replaces ``output_bundle_path``
    only after signing succeeded.

    Args:
        artifact_path: The release artifact; its basename becomes ``artifact.name``.
        package: Package name, pattern ``[a-z0-9][a-z0-9._-]{0,63}``.
        version: Release version, pattern ``[A-Za-z0-9][A-Za-z0-9._+-]{0,63}``.
        private_key_path: Unencrypted PKCS#8 PEM private key.
        output_bundle_path: Bundle JSON to write; must differ from the inputs.
        adapter: Key adapter; defaults to the dispatcher `zhongli.keys`.

    Returns:
        A `SignResult` with profile, keyid, manifest and signature bytes.

    Raises:
        OSError: an input cannot be read or the bundle cannot be written.
        ValueError: invalid key, metadata or output path (exit code 2 in the CLI).

    Example:
        >>> result = sign("dist/contoh-app.zip", "contoh-app", "1.0.0", "publisher.key.pem", "release.json")
        >>> result.algorithm, len(result.signature_bytes)
        ('ecdsa-p256-sha256', 64)
    """
    artifact_path, private_key_path, output = map(Path, (
        artifact_path, private_key_path, output_bundle_path
    ))
    _check_output(output, (artifact_path, private_key_path))
    private = adapter.load_private_key(private_key_path.read_bytes())
    public = adapter.public_from_private(private)
    profile, keyid = adapter.profile_of(private), adapter.fingerprint(public)
    artifact = read_artifact(artifact_path)
    manifest = serialize_manifest(build_manifest(package, version, profile, keyid, artifact))
    signature = adapter.sign_bytes(private, manifest)
    bundle = encode_bundle(manifest, signature)
    # Replace only after all validation, signing and writing succeeded.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=f".{output.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(bundle)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return SignResult(profile, keyid, manifest, signature, output)
