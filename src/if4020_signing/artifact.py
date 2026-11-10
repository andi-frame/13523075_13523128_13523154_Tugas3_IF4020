"""Read artifact bytes without normalizing, extracting or executing them."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from .formats import FormatError, MAX_ARTIFACT_SIZE, NAME_PATTERN


@dataclass(frozen=True)
class ArtifactInfo:
    name: str
    size: int
    sha256: str


def read_artifact(path: str | Path) -> ArtifactInfo:
    path = Path(path)
    if re.fullmatch(NAME_PATTERN, path.name) is None:
        raise FormatError("Invalid artifact basename")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ARTIFACT_SIZE:
                raise FormatError("Artifact exceeds maximum size")
            digest.update(chunk)
    return ArtifactInfo(path.name, size, digest.hexdigest())
