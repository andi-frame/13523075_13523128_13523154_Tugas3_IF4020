"""Collect raw signing measurements per profile.

    uv run python benchmarks/run.py --out evidence/benchmarks/<new-run>
    uv run python benchmarks/run.py --out <dir> --algorithm ecdsa-p256-sha256

Each profile is written to ``<out>/<profile>/``; ``<out>/summary.md`` compares them.
"""

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

from cryptography.hazmat.backends.openssl import backend as openssl_backend

from zhongli import keys
from zhongli.artifact import read_artifact
from zhongli.formats import build_manifest, encode_bundle, serialize_manifest
from zhongli.signing import sign
from zhongli.trust import add_trust
from zhongli.verification import Status, verify


def summarize(samples):
    ordered = sorted(samples)
    return {"n": len(ordered), "median_ns": statistics.median(ordered),
            "p95_ns": ordered[math.ceil(0.95 * len(ordered)) - 1]}


def run_benchmark(adapter, output: Path, *, iterations=30, warmups=5, keygens=5,
                  sizes=(1024, 1024**2, 10 * 1024**2)):
    """Shared harness: adapter must implement the documented crypto contract.

    ``crypto_*`` rows time the adapter on manifest bytes only. ``*_end_to_end``
    rows time the in-process application functions, including file I/O, key
    loading, artifact hashing, parsing and (for sign) the atomic bundle write.
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
        store_path = root / "trust.json"
        add_trust(store_path, adapter.export_public_spki_pem(pair.public_key), "benchmark")
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

            def crypto_verify():
                if not adapter.verify_bytes(pair.public_key, manifest, signature):
                    raise ValueError("Signature verification failed during benchmark")

            measure("crypto_verify", size, crypto_verify)
            bundle_path = root / "bundle.json"
            measure("sign_end_to_end", size, lambda: sign(artifact, "benchmark", "1.0",
                    private_path, bundle_path, adapter=adapter))

            def verify_end_to_end():
                result = verify(artifact, bundle_path, store_path, "benchmark", "1.0")
                if result.status is not Status.OK:
                    raise ValueError(f"Application verification failed during benchmark: {result.status}")

            measure("verify_end_to_end", size, verify_end_to_end)
    with (output / "raw.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=("operation", "artifact_bytes", "iteration", "elapsed_ns"), lineterminator="\n")
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
        "cryptography_openssl": openssl_backend.openssl_version_text(),
        "python_ssl": ssl.OPENSSL_VERSION,
        "iterations": iterations, "warmups": warmups, "keygens": keygens,
        "clock": "perf_counter_ns", "p95_method": "nearest rank ceil(0.95*n)",
        "dataset": dataset, "key_sizes": key_sizes,
        "scope": ("In-process; crypto includes profile hashing; end-to-end sign includes key load, "
                  "artifact read/hash, serialization and atomic fsync/write; end-to-end verify includes "
                  "bundle and trust store reads, strict parsing, key validation, signature, metadata "
                  "and artifact checks. Interpreter start-up is excluded."),
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return metadata, summary


def _format_ns(value: float) -> str:
    if value >= 1e6:
        return f"{value / 1e6:.3f} ms"
    return f"{value / 1e3:.1f} µs"


def write_comparison(output: Path, results: dict) -> None:
    """Write a Markdown table comparing the profiles measured in one run."""
    lines = ["# Benchmark summary", "",
             "Median / nearest-rank P95 per operation. Raw samples: `<profile>/raw.csv`.", ""]
    first = next(iter(results.values()))[0]
    lines += [f"Environment: {first['cpu']}, {first['os']}, Python {first['python']}, "
              f"cryptography {first['cryptography']} ({first['cryptography_openssl']}).", ""]
    lines += ["| Profile | Operation | Artifact bytes | n | Median | P95 |", "| --- | --- | ---: | ---: | ---: | ---: |"]
    for profile, (_, summary) in results.items():
        for row in summary:
            lines.append(f"| `{profile}` | {row['operation']} | {row['artifact_bytes']} | {row['n']} | "
                         f"{_format_ns(row['median_ns'])} | {_format_ns(row['p95_ns'])} |")
    lines += ["", "| Profile | Private key DER | Public key DER | Signature | Bundle (1 KiB artifact) |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for profile, (metadata, _) in results.items():
        sizes, dataset = metadata["key_sizes"][0], metadata["dataset"][0]
        lines.append(f"| `{profile}` | {sizes['private_pkcs8_der']} | {sizes['public_spki_der']} | "
                     f"{dataset['signature_bytes']} | {dataset['bundle_bytes']} |")
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True, help="New output directory")
    parser.add_argument("--algorithm", action="append", choices=keys.PROFILES,
                        help="profile to measure; repeatable (default: all)")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results = {}
    for profile in args.algorithm or keys.PROFILES:
        results[profile] = run_benchmark(keys.adapter_for_profile(profile), args.out / profile)
        print(f"{profile}: wrote raw.csv, metadata.json and summary.json to {args.out / profile}")
    write_comparison(args.out, results)
