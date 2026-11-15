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
    """Sign with the profile derived from the private key via the key dispatcher.

    OSError propagates as an input/environment failure. Key and format validation
    errors propagate as ValueError subclasses for the command to map to exit 2.
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
