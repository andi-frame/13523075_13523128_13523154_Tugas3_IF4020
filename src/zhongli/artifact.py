"""Read artifact bytes without normalizing, extracting or executing them."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import BinaryIO

from .formats import FormatError, MAX_ARTIFACT_SIZE, NAME_PATTERN

CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class ArtifactInfo:
    name: str
    size: int
    sha256: str


def digest_stream(stream: BinaryIO) -> tuple[int, str]:
    """Return the byte count and lowercase SHA-256 of everything left in ``stream``."""
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(CHUNK_SIZE):
        size += len(chunk)
        if size > MAX_ARTIFACT_SIZE:
            raise FormatError("Artifact exceeds maximum size")
        digest.update(chunk)
    return size, digest.hexdigest()


def read_artifact(path: str | Path) -> ArtifactInfo:
    path = Path(path)
    if re.fullmatch(NAME_PATTERN, path.name) is None:
        raise FormatError("Invalid artifact basename")
    with path.open("rb") as stream:
        size, sha256 = digest_stream(stream)
    return ArtifactInfo(path.name, size, sha256)
