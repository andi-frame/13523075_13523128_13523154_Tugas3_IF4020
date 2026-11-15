"""Trust store (``minisign-trust/v1``): strict validation, lookup and atomic updates.

Every entry is validated on load. Updates go to a temp file in the same
directory and replace the store only after the write completed.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from . import keys
from .formats import FormatError, HEX_PATTERN, PACKAGE_PATTERN, parse_json_strict

SCHEMA = "minisign-trust/v1"
# Internal limit, not part of the spec.
TRUST_STORE_LIMIT = 1024 * 1024
_ENTRY_FIELDS = ("keyid", "algorithm", "public_key_pem", "packages")


class KeyNotTrustedError(ValueError):
    """The key is absent, has another profile, or is not allowed for the package."""


class TrustKeyNotFoundError(LookupError):
    """``trust remove`` was asked to remove a keyid that is not in the store."""


@dataclass(frozen=True)
class TrustEntry:
    keyid: str
    algorithm: str
    public_key_pem: str
    packages: tuple[str, ...]
    public_key: Any

    def to_json(self) -> dict:
        return {"keyid": self.keyid, "algorithm": self.algorithm,
                "public_key_pem": self.public_key_pem, "packages": list(self.packages)}


@dataclass(frozen=True)
class TrustStore:
    entries: tuple[TrustEntry, ...]

    def get(self, keyid: str) -> TrustEntry | None:
        return next((entry for entry in self.entries if entry.keyid == keyid), None)


@dataclass(frozen=True)
class AddResult:
    entry: TrustEntry
    package: str
    changed: bool
    created_store: bool


def _fields(value: Any, names: tuple[str, ...], where: str) -> None:
    if type(value) is not dict or set(value) != set(names):
        raise FormatError(f"{where}: expected exactly these fields: {', '.join(names)}")


def _validate_entry(raw: Any, index: int) -> TrustEntry:
    where = f"keys[{index}]"
    _fields(raw, _ENTRY_FIELDS, where)
    keyid, algorithm, pem, packages = (raw[name] for name in _ENTRY_FIELDS)
    if type(keyid) is not str or re.fullmatch(HEX_PATTERN, keyid) is None:
        raise FormatError(f"{where}.keyid must be 64 lowercase hex characters")
    if type(algorithm) is not str or algorithm not in keys.PROFILES:
        raise FormatError(f"{where}.algorithm is not a supported profile")
    if type(pem) is not str:
        raise FormatError(f"{where}.public_key_pem must be a string")
    try:
        public_key = keys.load_public_key_for_profile(pem.encode("ascii"), algorithm)
    except (UnicodeError, ValueError) as exc:
        raise FormatError(f"{where}.public_key_pem is not a valid {algorithm} key: {exc}") from exc
    if keys.fingerprint(public_key) != keyid:
        raise FormatError(f"{where}.keyid does not match public_key_pem")
    if type(packages) is not list or not packages:
        raise FormatError(f"{where}.packages must be a non-empty array")
    for package in packages:
        if type(package) is not str or re.fullmatch(PACKAGE_PATTERN, package) is None:
            raise FormatError(f"{where}.packages contains an invalid package name or wildcard")
    if len(set(packages)) != len(packages):
        raise FormatError(f"{where}.packages contains duplicates")
    return TrustEntry(keyid, algorithm, pem, tuple(packages), public_key)


def parse_trust_store_strict(raw_bytes: bytes) -> TrustStore:
    """Parse and validate a ``minisign-trust/v1`` document.

    Every entry is checked: exactly the fields ``keyid``, ``algorithm``,
    ``public_key_pem`` and ``packages``; the key loads under its profile with
    the profile's parameters; the keyid equals the key's fingerprint; packages
    are a non-empty list of unique names without wildcards; keyids are unique.

    Raises:
        FormatError: any check fails, the file exceeds 1 MiB or starts with a BOM.
    """
    if len(raw_bytes) > TRUST_STORE_LIMIT:
        raise FormatError("Trust store exceeds 1 MiB")
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise FormatError("Trust store must be UTF-8 without BOM")
    data = parse_json_strict(raw_bytes)
    _fields(data, ("schema", "keys"), "trust store")
    if data["schema"] != SCHEMA:
        raise FormatError("Unknown trust store schema")
    if type(data["keys"]) is not list:
        raise FormatError("trust store keys must be an array")
    entries = tuple(_validate_entry(raw, index) for index, raw in enumerate(data["keys"]))
    if len({entry.keyid for entry in entries}) != len(entries):
        raise FormatError("Trust store contains duplicate keyid entries")
    return TrustStore(entries)


def load_trust_store(path: str | Path) -> TrustStore:
    """Read and validate a trust store file. OSError propagates as an I/O failure."""
    return parse_trust_store_strict(Path(path).read_bytes())


def find_authorized_key(store: TrustStore, keyid: str, profile: str, expected_package: str):
    """Return the public key for ``keyid`` if it may sign ``expected_package`` under ``profile``.

    There is no fallback to other keys or profiles.

    Raises:
        KeyNotTrustedError: the keyid is absent, is trusted under another
            profile, or is not allowed for the package.
    """
    entry = store.get(keyid)
    if entry is None:
        raise KeyNotTrustedError(f"Key {keyid} is not in the trust store")
    if entry.algorithm != profile:
        raise KeyNotTrustedError(f"Trusted key {keyid} has profile {entry.algorithm}, manifest uses {profile}")
    if expected_package not in entry.packages:
        raise KeyNotTrustedError(f"Key {keyid} is not allowed to sign package {expected_package}")
    return entry.public_key


def serialize_trust_store(store: TrustStore) -> bytes:
    """Encode a trust store as ASCII JSON with two-space indentation."""
    data = {"schema": SCHEMA, "keys": [entry.to_json() for entry in store.entries]}
    return (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def add_trust(store_path: str | Path, public_key_pem: bytes, package: str) -> AddResult:
    """Allow the key in ``public_key_pem`` to sign ``package``.

    Creates the store if it does not exist. If the key is already trusted, the
    package is added to its list; if it is already allowed, nothing changes.
    An existing but invalid store is never overwritten.

    Args:
        store_path: Trust store JSON file.
        public_key_pem: SPKI PEM bytes of the publisher's public key.
        package: Package name the key may sign; no wildcards.

    Raises:
        ValueError: invalid package name, invalid key, or invalid existing store.
        OSError: the store cannot be read or written.

    Example:
        >>> result = add_trust("trust.json", open("publisher.pub.pem", "rb").read(), "contoh-app")
        >>> result.changed, result.entry.algorithm
        (True, 'ecdsa-p256-sha256')
    """
    if type(package) is not str or re.fullmatch(PACKAGE_PATTERN, package) is None:
        raise ValueError(f"Invalid package name: {package!r}")
    public_key = keys.load_public_key(public_key_pem)
    algorithm = keys.profile_of(public_key)
    keyid = keys.fingerprint(public_key)
    pem = keys.export_public_spki_pem(public_key).decode("ascii")
    path = Path(store_path)
    created = not path.exists()
    # A broken store is an error, never treated as empty.
    store = TrustStore(()) if created else load_trust_store(path)
    entries = list(store.entries)
    existing = store.get(keyid)
    if existing is not None and package in existing.packages:
        return AddResult(existing, package, changed=False, created_store=False)
    if existing is not None:
        entry = TrustEntry(keyid, existing.algorithm, existing.public_key_pem,
                           existing.packages + (package,), existing.public_key)
        entries[entries.index(existing)] = entry
    else:
        entry = TrustEntry(keyid, algorithm, pem, (package,), public_key)
        entries.append(entry)
    _write_atomic(path, serialize_trust_store(TrustStore(tuple(entries))))
    return AddResult(entry, package, changed=True, created_store=created)


def list_trust(store_path: str | Path) -> tuple[TrustEntry, ...]:
    """Return the validated entries of a trust store, in file order."""
    return load_trust_store(store_path).entries


def remove_trust(store_path: str | Path, keyid: str) -> TrustEntry:
    """Remove the entry for ``keyid`` and return it.

    Raises:
        TrustKeyNotFoundError: ``keyid`` is not in the store.
        FormatError: the store is invalid; it is left unchanged.
    """
    path = Path(store_path)
    store = load_trust_store(path)
    entry = store.get(keyid)
    if entry is None:
        raise TrustKeyNotFoundError(f"Key {keyid} is not in the trust store")
    remaining = tuple(item for item in store.entries if item.keyid != keyid)
    _write_atomic(path, serialize_trust_store(TrustStore(remaining)))
    return entry
