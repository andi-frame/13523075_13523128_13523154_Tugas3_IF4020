"""Generate a key pair for a profile and write ``<prefix>.key.pem`` / ``<prefix>.pub.pem``."""

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile

from . import keys


@dataclass(frozen=True)
class KeygenResult:
    algorithm: str
    keyid: str
    private_key_path: Path
    public_key_path: Path


def _temporary(directory: Path, name: str, data: bytes, mode: int) -> Path:
    with tempfile.NamedTemporaryFile(dir=directory, prefix=f".{name}.", delete=False) as stream:
        path = Path(stream.name)
        try:
            os.chmod(path, mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    return path


def keygen(profile: str, output_prefix: str | os.PathLike, overwrite_explicit: bool = False) -> KeygenResult:
    """Existing key files are only replaced when ``overwrite_explicit`` is true.

    Unsupported profiles raise ValueError; I/O problems raise OSError.
    """
    adapter = keys.adapter_for_profile(profile)
    prefix = Path(output_prefix)
    if not prefix.name or prefix.name in (".", ".."):
        raise ValueError(f"Invalid output prefix: {output_prefix!s}")
    private_path = prefix.with_name(prefix.name + ".key.pem")
    public_path = prefix.with_name(prefix.name + ".pub.pem")
    if not overwrite_explicit:
        for path in (private_path, public_path):
            if path.exists() or path.is_symlink():
                raise FileExistsError(f"{path} already exists; pass --force to overwrite")
    directory = prefix.parent
    directory.mkdir(parents=True, exist_ok=True)

    pair = adapter.generate_keypair(profile)
    private_pem = adapter.export_private_pkcs8_pem(pair.private_key)
    public_pem = adapter.export_public_spki_pem(pair.public_key)
    keyid = adapter.fingerprint(pair.public_key)

    # Both files are fully written before either target is replaced.
    temporaries = []
    try:
        temporaries.append(_temporary(directory, private_path.name, private_pem, 0o600))
        temporaries.append(_temporary(directory, public_path.name, public_pem, 0o644))
        os.replace(temporaries[0], private_path)
        os.replace(temporaries[1], public_path)
    finally:
        for path in temporaries:
            path.unlink(missing_ok=True)
    return KeygenResult(profile, keyid, private_path, public_path)
