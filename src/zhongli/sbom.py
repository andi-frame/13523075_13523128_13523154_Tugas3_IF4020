"""Signed SBOM: a CycloneDX 1.6 JSON SBOM bound to one release artifact.

The SBOM is an ordinary file that is signed with the normal ``sign`` flow, so
its signature lives in a ``minisign-bundle/v1`` bundle and its key is checked
against the same ``minisign-trust/v1`` trust store as the release. What makes
it an SBOM *of that release* is the binding check in `verify_release_with_sbom`:

1. the release bundle verifies against the artifact (all checks of `verify`);
2. the SBOM bundle verifies against the SBOM file (all checks of `verify`);
3. the SBOM, parsed from the exact bytes that were verified, names the release
   artifact by the same SHA-256, size and file name as the verified release
   manifest, and the same package and version.

Step 3 is what catches a replaced artifact that was re-signed with a trusted
key while the old SBOM was kept, or a valid SBOM taken from another release.

The SBOM records the artifact in ``metadata.component``:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "tools": {"components": [{"type": "application", "name": "zhongli", "version": "0.1.2"}]},
    "component": {
      "type": "application",
      "bom-ref": "release-artifact",
      "name": "contoh-app",
      "version": "1.0.0",
      "hashes": [{"alg": "SHA-256", "content": "<64 lowercase hex>"}],
      "properties": [
        {"name": "zhongli:artifact:name", "value": "contoh-app.zip"},
        {"name": "zhongli:artifact:size", "value": "12345"}
      ]
    }
  },
  "components": [
    {"type": "library", "bom-ref": "pkg:pypi/cryptography@50.0.2", "name": "cryptography",
     "version": "50.0.2", "purl": "pkg:pypi/cryptography@50.0.2"}
  ]
}
```

Components are read from a ``uv.lock`` file when one is given: the runtime
dependencies of the locked project, without development groups.
"""

from dataclasses import dataclass
import hashlib
from importlib.metadata import version as installed_version
import json
import os
from pathlib import Path
import re
import tempfile
import tomllib
from typing import Any
import uuid

from .artifact import ArtifactInfo, read_artifact
from .formats import (
    HEX_PATTERN, MAX_ARTIFACT_SIZE, NAME_PATTERN, PACKAGE_PATTERN, VERSION_PATTERN,
    FormatError, parse_json_strict,
)
from .signing import SignResult, sign
from .verification import Status, VerificationResult, verify_with_manifest

SBOM_LIMIT = 1024 * 1024
"""Largest accepted SBOM file in bytes."""
SPEC_VERSION = "1.6"
"""CycloneDX specification version that is written and accepted."""
SBOM_MISMATCH = "SBOM_MISMATCH"
"""Status of `verify_release_with_sbom` when both bundles are valid but the SBOM
does not describe the verified artifact."""
ARTIFACT_NAME_PROPERTY = "zhongli:artifact:name"
ARTIFACT_SIZE_PROPERTY = "zhongli:artifact:size"


class SbomError(FormatError):
    """The SBOM is not a CycloneDX 1.6 JSON SBOM in the form this program binds."""


@dataclass(frozen=True)
class SbomSubject:
    """The release artifact an SBOM describes, as read from ``metadata.component``."""

    package: str
    version: str
    artifact_name: str
    artifact_size: int
    artifact_sha256: str
    component_count: int


@dataclass(frozen=True)
class SbomVerificationResult:
    """Outcome of `verify_release_with_sbom`.

    Attributes:
        status: ``"OK"``, one of the `Status` values of the failing bundle check,
            or ``"SBOM_MISMATCH"``.
        stage: ``None`` when valid; otherwise ``"artifact"`` (release bundle),
            ``"sbom"`` (SBOM bundle or SBOM content) or ``"binding"``.
        message: Human-readable reason.
        artifact: Result of verifying the release bundle.
        sbom: Result of verifying the SBOM bundle.
        binding: The compared values once both bundles verified, else ``None``.
    """

    status: str
    stage: str | None
    message: str
    artifact: VerificationResult
    sbom: VerificationResult
    binding: dict[str, Any] | None = None

    @property
    def valid(self) -> bool:
        return self.status == Status.OK

    @property
    def exit_code(self) -> int:
        """0 when valid, 2 for ``INPUT_ERROR``, 1 for every rejection."""
        if self.valid:
            return 0
        return 2 if self.status == Status.INPUT_ERROR else 1

    def to_json(self) -> dict[str, Any]:
        return {
            "valid": self.valid, "status": str(self.status), "stage": self.stage,
            "message": self.message, "artifact": self.artifact.to_json(),
            "sbom": self.sbom.to_json(), "binding": self.binding,
        }


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"


def read_lock_components(lock_path: str | os.PathLike) -> list[dict[str, str]]:
    """Return the runtime dependencies of the project locked in a ``uv.lock`` file.

    The project is the package whose source is the lock file's own directory
    (``editable`` or ``virtual`` ``"."``). Its ``dependencies`` are followed
    transitively; development groups and optional extras are not included.

    Returns:
        ``[{"name": ..., "version": ...}, ...]`` sorted by name and version.

    Raises:
        ValueError: the file is not a valid lock file or has no project entry.
        OSError: the file cannot be read.
    """
    try:
        lock = tomllib.loads(Path(lock_path).read_text(encoding="utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"Invalid lock file: {exc}") from exc
    packages = lock.get("package")
    if type(packages) is not list:
        raise ValueError("Lock file has no [[package]] entries")
    by_name: dict[str, list[dict]] = {}
    roots = []
    for entry in packages:
        if type(entry) is not dict or type(entry.get("name")) is not str or type(entry.get("version")) is not str:
            continue
        by_name.setdefault(entry["name"], []).append(entry)
        source = entry.get("source")
        if type(source) is dict and "." in (source.get("editable"), source.get("virtual")):
            roots.append(entry)
    if not roots:
        raise ValueError("Lock file has no project entry with source \".\"")

    found: dict[tuple[str, str], dict[str, str]] = {}
    pending = [dep.get("name") for root in roots for dep in root.get("dependencies", [])]
    seen: set[str] = set()
    while pending:
        name = pending.pop()
        if type(name) is not str or name in seen:
            continue
        seen.add(name)
        for entry in by_name.get(name, []):
            found[(entry["name"], entry["version"])] = {"name": entry["name"], "version": entry["version"]}
            pending.extend(dep.get("name") for dep in entry.get("dependencies", []))
    return [found[key] for key in sorted(found)]


def build_sbom(artifact: ArtifactInfo, package: str, version: str,
               components: list[dict[str, str]] = ()) -> dict[str, Any]:
    """Build the CycloneDX document for ``artifact``.

    The output is deterministic: the serial number is a UUIDv5 of package,
    version and artifact SHA-256, and no timestamp is written, so the same
    inputs always give the same SBOM bytes.

    Raises:
        SbomError: package, version or a component has an invalid value.
    """
    for field, value, pattern in (("package", package, PACKAGE_PATTERN), ("version", version, VERSION_PATTERN)):
        if type(value) is not str or re.fullmatch(pattern, value) is None:
            raise SbomError(f"Invalid {field}: {value!r}")
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"zhongli:sbom:{package}:{version}:{artifact.sha256}")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [
                {"type": "application", "name": "zhongli", "version": installed_version("zhongli")},
            ]},
            "component": {
                "type": "application",
                "bom-ref": "release-artifact",
                "name": package,
                "version": version,
                "hashes": [{"alg": "SHA-256", "content": artifact.sha256}],
                "properties": [
                    {"name": ARTIFACT_NAME_PROPERTY, "value": artifact.name},
                    {"name": ARTIFACT_SIZE_PROPERTY, "value": str(artifact.size)},
                ],
            },
        },
        "components": [
            {"type": "library", "bom-ref": _purl(item["name"], item["version"]), "name": item["name"],
             "version": item["version"], "purl": _purl(item["name"], item["version"])}
            for item in components
        ],
    }
    parse_sbom_strict(serialize_sbom(sbom))
    return sbom


def serialize_sbom(sbom: dict[str, Any]) -> bytes:
    """Encode an SBOM as UTF-8 JSON with two-space indentation and a final newline."""
    return (json.dumps(sbom, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _string(value: Any, pattern: str, field: str) -> str:
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise SbomError(f"Invalid SBOM {field}")
    return value


def parse_sbom_strict(raw_bytes: bytes) -> SbomSubject:
    """Parse an SBOM and return the release artifact it describes.

    Checks that the document is UTF-8 JSON without BOM or duplicate fields, at
    most `SBOM_LIMIT` bytes, ``bomFormat`` ``"CycloneDX"`` and ``specVersion``
    ``"1.6"``, and that ``metadata.component`` has a valid name and version,
    exactly one ``SHA-256`` hash in lowercase hex, and exactly one artifact
    name and size property. Other CycloneDX fields are allowed and ignored.

    Raises:
        SbomError: any of the checks fails.
    """
    if len(raw_bytes) > SBOM_LIMIT:
        raise SbomError("SBOM exceeds 1 MiB")
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise SbomError("SBOM must be UTF-8 without BOM")
    try:
        data = parse_json_strict(raw_bytes)
    except FormatError as exc:
        raise SbomError(f"SBOM is not valid JSON: {exc}") from exc
    if type(data) is not dict or data.get("bomFormat") != "CycloneDX":
        raise SbomError("SBOM bomFormat must be \"CycloneDX\"")
    if data.get("specVersion") != SPEC_VERSION:
        raise SbomError(f"SBOM specVersion must be \"{SPEC_VERSION}\"")
    if type(data.get("version")) is not int or data["version"] < 1:
        raise SbomError("SBOM version must be a positive integer")
    metadata = data.get("metadata")
    component = metadata.get("component") if type(metadata) is dict else None
    if type(component) is not dict:
        raise SbomError("SBOM metadata.component is missing")
    package = _string(component.get("name"), PACKAGE_PATTERN, "metadata.component.name")
    version = _string(component.get("version"), VERSION_PATTERN, "metadata.component.version")

    hashes = component.get("hashes")
    if type(hashes) is not list:
        raise SbomError("SBOM metadata.component.hashes must be an array")
    sha256 = [item.get("content") for item in hashes if type(item) is dict and item.get("alg") == "SHA-256"]
    if len(sha256) != 1:
        raise SbomError("SBOM metadata.component must have exactly one SHA-256 hash")
    sha256 = _string(sha256[0], HEX_PATTERN, "metadata.component SHA-256")

    properties = component.get("properties")
    if type(properties) is not list or any(type(item) is not dict for item in properties):
        raise SbomError("SBOM metadata.component.properties must be an array of objects")
    values = {}
    for name in (ARTIFACT_NAME_PROPERTY, ARTIFACT_SIZE_PROPERTY):
        matches = [item.get("value") for item in properties if item.get("name") == name]
        if len(matches) != 1:
            raise SbomError(f"SBOM metadata.component must have exactly one {name} property")
        values[name] = matches[0]
    name = _string(values[ARTIFACT_NAME_PROPERTY], NAME_PATTERN, ARTIFACT_NAME_PROPERTY)
    size_text = _string(values[ARTIFACT_SIZE_PROPERTY], r"0|[1-9][0-9]{0,15}", ARTIFACT_SIZE_PROPERTY)
    if int(size_text) > MAX_ARTIFACT_SIZE:
        raise SbomError(f"Invalid SBOM {ARTIFACT_SIZE_PROPERTY}")

    components = data.get("components", [])
    if type(components) is not list or any(
        type(item) is not dict or type(item.get("name")) is not str for item in components
    ):
        raise SbomError("SBOM components must be an array of objects with a name")
    return SbomSubject(package, version, name, int(size_text), sha256, len(components))


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def create_sbom(artifact_path: str | os.PathLike, package: str, version: str,
                output_path: str | os.PathLike, lock_path: str | os.PathLike | None = None) -> SbomSubject:
    """Hash ``artifact_path`` and write its SBOM to ``output_path``.

    Args:
        artifact_path: The release artifact the SBOM describes.
        package: Package name, as later passed to ``sign`` and ``verify``.
        version: Release version.
        output_path: SBOM file to write; replaced atomically if it exists.
        lock_path: Optional ``uv.lock`` whose runtime dependencies become ``components``.

    Returns:
        The `SbomSubject` that was written.

    Raises:
        OSError: an input cannot be read or the output cannot be written.
        ValueError: invalid values, invalid lock file, or the output is the artifact.

    Example:
        >>> create_sbom("dist/contoh-app.zip", "contoh-app", "1.0.0", "sbom.json", lock_path="uv.lock")
        SbomSubject(package='contoh-app', version='1.0.0', artifact_name='contoh-app.zip', ...)
    """
    artifact_path, output = Path(artifact_path), Path(output_path)
    if output.resolve() == artifact_path.resolve():
        raise ValueError("SBOM output must differ from the artifact")
    components = read_lock_components(lock_path) if lock_path is not None else []
    data = serialize_sbom(build_sbom(read_artifact(artifact_path), package, version, components))
    _write_atomic(output, data)
    return parse_sbom_strict(data)


def sign_sbom(sbom_path: str | os.PathLike, package: str, version: str,
              private_key_path: str | os.PathLike, output_bundle_path: str | os.PathLike) -> SignResult:
    """Sign an SBOM file as a separate artifact with the normal bundle format.

    The SBOM is parsed first, and its ``metadata.component`` name and version
    must equal ``package`` and ``version``, so an SBOM is never signed for a
    release it does not describe.

    Raises:
        SbomError: the SBOM is invalid or describes another package or version.
        OSError, ValueError: as raised by `zhongli.signing.sign`.
    """
    subject = parse_sbom_strict(_read_limited(Path(sbom_path)))
    if (subject.package, subject.version) != (package, version):
        raise SbomError(f"SBOM describes {subject.package} {subject.version}, not {package} {version}")
    return sign(sbom_path, package, version, private_key_path, output_bundle_path)


def _read_limited(path: Path) -> bytes:
    with path.open("rb") as stream:
        return stream.read(SBOM_LIMIT + 1)


def verify_release_with_sbom(
    artifact_path: str | os.PathLike, bundle_path: str | os.PathLike,
    sbom_path: str | os.PathLike, sbom_bundle_path: str | os.PathLike,
    trust_store_path: str | os.PathLike, expected_package: str, expected_version: str,
) -> SbomVerificationResult:
    """Verify the release bundle, the SBOM bundle, and the binding between them.

    Both bundles are verified with the same trust store, package and version.
    The overall status is the first failure in this order: an ``INPUT_ERROR``
    in either check, the release bundle, the SBOM bundle, the SBOM content
    (``FORMAT_ERROR``), and finally the binding (``SBOM_MISMATCH``).

    Example:
        >>> result = verify_release_with_sbom(
        ...     "dist/contoh-app.zip", "release.json", "sbom.json", "sbom.bundle.json",
        ...     "trust.json", "contoh-app", "1.0.0")
        >>> result.status, result.exit_code
        ('OK', 0)
    """
    artifact_result, release_manifest = verify_with_manifest(
        artifact_path, bundle_path, trust_store_path, expected_package, expected_version)
    sbom_result, sbom_manifest = verify_with_manifest(
        sbom_path, sbom_bundle_path, trust_store_path, expected_package, expected_version)

    def result(status: str, stage: str | None, message: str, binding=None) -> SbomVerificationResult:
        return SbomVerificationResult(status, stage, message, artifact_result, sbom_result, binding)

    for stage, checked in (("artifact", artifact_result), ("sbom", sbom_result)):
        if checked.status is Status.INPUT_ERROR:
            return result(checked.status, stage, checked.message)
    for stage, checked in (("artifact", artifact_result), ("sbom", sbom_result)):
        if not checked.valid:
            return result(checked.status, stage, checked.message)

    # Parse the SBOM from bytes whose hash equals the verified SBOM manifest, so
    # the content checked here is the content the signature covers.
    try:
        sbom_bytes = _read_limited(Path(sbom_path))
    except OSError as exc:
        return result(Status.INPUT_ERROR, "sbom", f"Cannot read {sbom_path}: {exc.strerror or exc}")
    if (len(sbom_bytes), hashlib.sha256(sbom_bytes).hexdigest()) != (
        sbom_manifest["artifact"]["size"], sbom_manifest["artifact"]["sha256"]
    ):
        return result(Status.ARTIFACT_MISMATCH, "sbom", "SBOM changed after its signature was verified")
    try:
        subject = parse_sbom_strict(sbom_bytes)
    except SbomError as exc:
        return result(Status.FORMAT_ERROR, "sbom", str(exc))

    release = release_manifest["artifact"]
    binding = {
        "artifact_name": release["name"], "artifact_size": release["size"], "artifact_sha256": release["sha256"],
        "sbom_artifact_name": subject.artifact_name, "sbom_artifact_size": subject.artifact_size,
        "sbom_artifact_sha256": subject.artifact_sha256,
        "sbom_package": subject.package, "sbom_version": subject.version,
    }
    for field, expected, actual in (
        ("SHA-256", release["sha256"], subject.artifact_sha256),
        ("size", release["size"], subject.artifact_size),
        ("file name", release["name"], subject.artifact_name),
        ("package", expected_package, subject.package),
        ("version", expected_version, subject.version),
    ):
        if expected != actual:
            binding["match"] = False
            return result(SBOM_MISMATCH, "binding",
                          f"SBOM artifact {field} {actual!r} does not match the verified release {expected!r}",
                          binding)
    binding["match"] = True
    return result(Status.OK, None, "Release, SBOM and their binding are valid.", binding)
