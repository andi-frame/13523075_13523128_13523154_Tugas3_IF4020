# Benchmark summary

Median / nearest-rank P95 per operation. Raw samples: `<profile>/raw.csv`.

Environment: AMD Ryzen 7 5800H with Radeon Graphics, Linux-7.2.15-1-omarchy-x86_64-with-glibc2.44, Python 3.13.15, cryptography 50.0.2 (OpenSSL 4.0.3 29 Sep 2026).

| Profile | Operation | Artifact bytes | n | Median | P95 |
| --- | --- | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | keygen | 0 | 5 | 187.862 ms | 344.532 ms |
| `rsa-pss-sha256` | artifact_sha256 | 1024 | 30 | 17.1 µs | 37.7 µs |
| `rsa-pss-sha256` | crypto_sign | 1024 | 30 | 1.660 ms | 2.318 ms |
| `rsa-pss-sha256` | crypto_verify | 1024 | 30 | 43.0 µs | 51.5 µs |
| `rsa-pss-sha256` | sign_end_to_end | 1024 | 30 | 304.111 ms | 332.270 ms |
| `rsa-pss-sha256` | verify_end_to_end | 1024 | 30 | 99.742 ms | 167.084 ms |
| `rsa-pss-sha256` | artifact_sha256 | 1048576 | 30 | 983.1 µs | 1.797 ms |
| `rsa-pss-sha256` | crypto_sign | 1048576 | 30 | 1.640 ms | 1.875 ms |
| `rsa-pss-sha256` | crypto_verify | 1048576 | 30 | 42.2 µs | 47.4 µs |
| `rsa-pss-sha256` | sign_end_to_end | 1048576 | 30 | 308.218 ms | 357.077 ms |
| `rsa-pss-sha256` | verify_end_to_end | 1048576 | 30 | 83.933 ms | 100.811 ms |
| `rsa-pss-sha256` | artifact_sha256 | 10485760 | 30 | 7.375 ms | 8.374 ms |
| `rsa-pss-sha256` | crypto_sign | 10485760 | 30 | 1.686 ms | 2.193 ms |
| `rsa-pss-sha256` | crypto_verify | 10485760 | 30 | 63.2 µs | 74.5 µs |
| `rsa-pss-sha256` | sign_end_to_end | 10485760 | 30 | 308.131 ms | 328.089 ms |
| `rsa-pss-sha256` | verify_end_to_end | 10485760 | 30 | 94.370 ms | 111.562 ms |
| `ecdsa-p256-sha256` | keygen | 0 | 5 | 16.3 µs | 92.3 µs |
| `ecdsa-p256-sha256` | artifact_sha256 | 1024 | 30 | 15.5 µs | 18.1 µs |
| `ecdsa-p256-sha256` | crypto_sign | 1024 | 30 | 27.5 µs | 31.8 µs |
| `ecdsa-p256-sha256` | crypto_verify | 1024 | 30 | 60.3 µs | 67.1 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 1024 | 30 | 84.106 ms | 90.177 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 1024 | 30 | 83.543 ms | 92.095 ms |
| `ecdsa-p256-sha256` | artifact_sha256 | 1048576 | 30 | 632.8 µs | 673.1 µs |
| `ecdsa-p256-sha256` | crypto_sign | 1048576 | 30 | 27.5 µs | 35.0 µs |
| `ecdsa-p256-sha256` | crypto_verify | 1048576 | 30 | 60.3 µs | 68.1 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 1048576 | 30 | 88.599 ms | 96.122 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 1048576 | 30 | 111.672 ms | 159.638 ms |
| `ecdsa-p256-sha256` | artifact_sha256 | 10485760 | 30 | 7.590 ms | 8.652 ms |
| `ecdsa-p256-sha256` | crypto_sign | 10485760 | 30 | 26.8 µs | 32.4 µs |
| `ecdsa-p256-sha256` | crypto_verify | 10485760 | 30 | 59.6 µs | 64.9 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 10485760 | 30 | 108.987 ms | 159.444 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 10485760 | 30 | 116.757 ms | 136.528 ms |
| `ed25519` | keygen | 0 | 5 | 33.9 µs | 91.3 µs |
| `ed25519` | artifact_sha256 | 1024 | 30 | 16.0 µs | 17.2 µs |
| `ed25519` | crypto_sign | 1024 | 30 | 30.3 µs | 30.8 µs |
| `ed25519` | crypto_verify | 1024 | 30 | 97.1 µs | 104.2 µs |
| `ed25519` | sign_end_to_end | 1024 | 30 | 97.977 ms | 150.717 ms |
| `ed25519` | verify_end_to_end | 1024 | 30 | 104.341 ms | 123.051 ms |
| `ed25519` | artifact_sha256 | 1048576 | 30 | 631.7 µs | 683.0 µs |
| `ed25519` | crypto_sign | 1048576 | 30 | 29.7 µs | 33.1 µs |
| `ed25519` | crypto_verify | 1048576 | 30 | 94.4 µs | 99.9 µs |
| `ed25519` | sign_end_to_end | 1048576 | 30 | 91.358 ms | 112.934 ms |
| `ed25519` | verify_end_to_end | 1048576 | 30 | 87.585 ms | 116.043 ms |
| `ed25519` | artifact_sha256 | 10485760 | 30 | 7.927 ms | 8.576 ms |
| `ed25519` | crypto_sign | 10485760 | 30 | 29.7 µs | 31.9 µs |
| `ed25519` | crypto_verify | 10485760 | 30 | 96.0 µs | 101.0 µs |
| `ed25519` | sign_end_to_end | 10485760 | 30 | 99.657 ms | 125.822 ms |
| `ed25519` | verify_end_to_end | 10485760 | 30 | 103.939 ms | 119.126 ms |

| Profile | Private key DER | Public key DER | Signature | Bundle (1 KiB artifact) |
| --- | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 1794 | 422 | 384 | 980 |
| `ecdsa-p256-sha256` | 138 | 91 | 64 | 560 |
| `ed25519` | 48 | 44 | 64 | 544 |
