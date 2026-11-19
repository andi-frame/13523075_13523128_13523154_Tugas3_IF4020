# Benchmark summary

Median / nearest-rank P95 per operation. Raw samples: `<profile>/raw.csv`.

Environment: AMD Ryzen 7 5800H with Radeon Graphics, Linux-7.2.15-1-omarchy-x86_64-with-glibc2.44, Python 3.13.15, cryptography 50.0.2 (OpenSSL 4.0.3 29 Sep 2026).

| Profile | Operation | Artifact bytes | n | Median | P95 |
| --- | --- | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | keygen | 0 | 5 | 218.931 ms | 400.312 ms |
| `rsa-pss-sha256` | artifact_sha256 | 1024 | 30 | 15.9 µs | 17.0 µs |
| `rsa-pss-sha256` | crypto_sign | 1024 | 30 | 1.646 ms | 1.829 ms |
| `rsa-pss-sha256` | crypto_verify | 1024 | 30 | 42.6 µs | 56.8 µs |
| `rsa-pss-sha256` | sign_end_to_end | 1024 | 30 | 297.541 ms | 328.314 ms |
| `rsa-pss-sha256` | verify_end_to_end | 1024 | 30 | 84.947 ms | 92.328 ms |
| `rsa-pss-sha256` | artifact_sha256 | 1048576 | 30 | 962.5 µs | 1.051 ms |
| `rsa-pss-sha256` | crypto_sign | 1048576 | 30 | 1.655 ms | 2.094 ms |
| `rsa-pss-sha256` | crypto_verify | 1048576 | 30 | 42.3 µs | 51.3 µs |
| `rsa-pss-sha256` | sign_end_to_end | 1048576 | 30 | 304.552 ms | 346.778 ms |
| `rsa-pss-sha256` | verify_end_to_end | 1048576 | 30 | 88.671 ms | 128.374 ms |
| `rsa-pss-sha256` | artifact_sha256 | 10485760 | 30 | 8.833 ms | 10.560 ms |
| `rsa-pss-sha256` | crypto_sign | 10485760 | 30 | 1.646 ms | 1.702 ms |
| `rsa-pss-sha256` | crypto_verify | 10485760 | 30 | 45.0 µs | 58.4 µs |
| `rsa-pss-sha256` | sign_end_to_end | 10485760 | 30 | 301.379 ms | 326.249 ms |
| `rsa-pss-sha256` | verify_end_to_end | 10485760 | 30 | 93.456 ms | 103.599 ms |
| `ecdsa-p256-sha256` | keygen | 0 | 5 | 16.4 µs | 219.4 µs |
| `ecdsa-p256-sha256` | artifact_sha256 | 1024 | 30 | 16.2 µs | 17.9 µs |
| `ecdsa-p256-sha256` | crypto_sign | 1024 | 30 | 28.2 µs | 38.6 µs |
| `ecdsa-p256-sha256` | crypto_verify | 1024 | 30 | 60.4 µs | 65.7 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 1024 | 30 | 86.844 ms | 95.786 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 1024 | 30 | 87.494 ms | 97.553 ms |
| `ecdsa-p256-sha256` | artifact_sha256 | 1048576 | 30 | 599.7 µs | 618.6 µs |
| `ecdsa-p256-sha256` | crypto_sign | 1048576 | 30 | 27.9 µs | 39.9 µs |
| `ecdsa-p256-sha256` | crypto_verify | 1048576 | 30 | 60.3 µs | 65.0 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 1048576 | 30 | 95.492 ms | 124.910 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 1048576 | 30 | 91.333 ms | 119.703 ms |
| `ecdsa-p256-sha256` | artifact_sha256 | 10485760 | 30 | 8.652 ms | 10.026 ms |
| `ecdsa-p256-sha256` | crypto_sign | 10485760 | 30 | 27.5 µs | 30.5 µs |
| `ecdsa-p256-sha256` | crypto_verify | 10485760 | 30 | 60.4 µs | 66.4 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 10485760 | 30 | 107.972 ms | 131.072 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 10485760 | 30 | 99.098 ms | 139.388 ms |
| `ed25519` | keygen | 0 | 5 | 35.2 µs | 75.1 µs |
| `ed25519` | artifact_sha256 | 1024 | 30 | 16.1 µs | 17.1 µs |
| `ed25519` | crypto_sign | 1024 | 30 | 29.9 µs | 32.0 µs |
| `ed25519` | crypto_verify | 1024 | 30 | 94.7 µs | 122.1 µs |
| `ed25519` | sign_end_to_end | 1024 | 30 | 81.260 ms | 94.195 ms |
| `ed25519` | verify_end_to_end | 1024 | 30 | 80.248 ms | 86.351 ms |
| `ed25519` | artifact_sha256 | 1048576 | 30 | 622.1 µs | 660.8 µs |
| `ed25519` | crypto_sign | 1048576 | 30 | 29.9 µs | 30.8 µs |
| `ed25519` | crypto_verify | 1048576 | 30 | 94.1 µs | 98.9 µs |
| `ed25519` | sign_end_to_end | 1048576 | 30 | 84.326 ms | 92.034 ms |
| `ed25519` | verify_end_to_end | 1048576 | 30 | 91.426 ms | 116.349 ms |
| `ed25519` | artifact_sha256 | 10485760 | 30 | 7.726 ms | 8.390 ms |
| `ed25519` | crypto_sign | 10485760 | 30 | 29.4 µs | 30.4 µs |
| `ed25519` | crypto_verify | 10485760 | 30 | 92.3 µs | 100.4 µs |
| `ed25519` | sign_end_to_end | 10485760 | 30 | 100.348 ms | 113.787 ms |
| `ed25519` | verify_end_to_end | 10485760 | 30 | 96.484 ms | 134.479 ms |

| Profile | Private key DER | Public key DER | Signature | Bundle (1 KiB artifact) |
| --- | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 1794 | 422 | 384 | 980 |
| `ecdsa-p256-sha256` | 138 | 91 | 64 | 560 |
| `ed25519` | 48 | 44 | 64 | 544 |
