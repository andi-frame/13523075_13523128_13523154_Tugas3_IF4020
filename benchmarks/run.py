"""Collect raw RSA measurements; run via `uv run python benchmarks/run.py`."""

import argparse
import csv
from importlib.metadata import version
import json
import math
import platform
from pathlib import Path
import statistics
import tempfile
from time import perf_counter_ns
import ssl

from if4020_signing.artifact import read_artifact
from if4020_signing.crypto import rsa
from if4020_signing.formats import build_manifest, encode_bundle, serialize_manifest
from if4020_signing.signing import sign


def summarize(samples):
    ordered = sorted(samples)
    return {"n": len(ordered), "median_ns": statistics.median(ordered),
            "p95_ns": ordered[math.ceil(0.95 * len(ordered)) - 1]}


def run_benchmark(adapter, output: Path, *, iterations=30, warmups=5, keygens=5,
                  sizes=(1024, 1024**2, 10 * 1024**2)):
    """Shared harness: adapter must implement the documented crypto contract.

    End-to-end verification must be added once the application verifier exists;
    crypto verification here does not measure trust/metadata/artifact checks.
    """
    if iterations < 30 or warmups < 5 or keygens < 5 or len(set(sizes)) < 3 or min(sizes) < 0:
        raise ValueError("Require >=30 samples, >=5 warmups, >=5 keygens and >=3 distinct sizes")
    output.mkdir(parents=True, exist_ok=False)
    rows, key_sizes, dataset = [], [], []

    def measure(operation, size, action, count=iterations, warming=warmups):
        for _ in range(warming):
            action()
        for iteration in range(count):
            start = perf_counter_ns()
            action()
            rows.append({"operation": operation, "artifact_bytes": size,
                         "iteration": iteration, "elapsed_ns": perf_counter_ns() - start})

    measure("keygen", 0, adapter.generate_keypair, count=keygens, warming=0)
    pair = adapter.generate_keypair()
    profile = adapter.profile_of(pair.private_key)
    key_sizes.append({"private_pkcs8_der": len(adapter.export_private_pkcs8_der(pair.private_key)),
                      "public_spki_der": len(adapter.export_public_spki_der(pair.public_key))})
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        private_path = root / "test.key.pem"
        private_path.write_bytes(adapter.export_private_pkcs8_pem(pair.private_key))
        for size in sizes:
            artifact = root / "artifact.bin"
            # Deterministic, identical bytes across algorithms; never used as RNG seed.
            block = bytes(range(256)) * 4096
            with artifact.open("wb") as stream:
                remaining = size
                while remaining:
                    chunk = block[:min(remaining, len(block))]
                    stream.write(chunk)
                    remaining -= len(chunk)
            info = read_artifact(artifact)
            manifest = serialize_manifest(build_manifest("benchmark", "1.0", profile,
                                adapter.fingerprint(pair.public_key), info))
            signature = adapter.sign_bytes(pair.private_key, manifest)
            if not adapter.verify_bytes(pair.public_key, manifest, signature):
                raise ValueError("Benchmark signature failed verification")
            dataset.append({"artifact_bytes": size, "sha256": info.sha256,
                            "manifest_bytes": len(manifest), "signature_bytes": len(signature),
                            "bundle_bytes": len(encode_bundle(manifest, signature))})
            measure("artifact_sha256", size, lambda: read_artifact(artifact))
            measure("crypto_sign", size, lambda: adapter.sign_bytes(pair.private_key, manifest))

            def verify():
                if not adapter.verify_bytes(pair.public_key, manifest, signature):
                    raise ValueError("Signature verification failed during benchmark")

            measure("crypto_verify", size, verify)
            measure("sign_end_to_end", size, lambda: sign(artifact, "benchmark", "1.0",
                    private_path, root / "bundle.json", adapter=adapter))
    with (output / "raw.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("operation", "artifact_bytes", "iteration", "elapsed_ns"))
        writer.writeheader()
        writer.writerows(rows)
    summary = []
    for operation, size in dict.fromkeys((row["operation"], row["artifact_bytes"]) for row in rows):
        summary.append({"operation": operation, "artifact_bytes": size,
                        **summarize([row["elapsed_ns"] for row in rows
                                     if row["operation"] == operation and row["artifact_bytes"] == size])})
    cpu = platform.processor()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo.read_text().splitlines()
                    if line.startswith("model name")), cpu)
    metadata = {
        "algorithm": profile, "python": platform.python_version(), "os": platform.platform(),
        "machine": platform.machine(), "cpu": cpu, "cryptography": version("cryptography"),
        "python_ssl": ssl.OPENSSL_VERSION,
        "iterations": iterations, "warmups": warmups, "keygens": keygens,
        "clock": "perf_counter_ns", "p95_method": "nearest rank ceil(0.95*n)",
        "dataset": dataset, "key_sizes": key_sizes,
        "scope": "In-process; crypto includes profile hashing; end-to-end sign includes key load, artifact read/hash, serialization and atomic fsync/write.",
        "missing": ["Application verify end-to-end (verifier not implemented)"],
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New output directory")
    args = parser.parse_args()
    run_benchmark(rsa, args.out)
    print(f"Wrote raw.csv, metadata.json and summary.json to {args.out}")
