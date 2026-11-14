# Benchmark summary

Median / nearest-rank P95 per operation. Raw samples: `<profile>/raw.csv`.

Environment: 12th Gen Intel(R) Core(TM) i5-12500H, Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.36, Python 3.13.18, cryptography 50.0.2 (OpenSSL 4.0.3 29 Sep 2026).

| Profile | Operation | Artifact bytes | n | Median | P95 |
| --- | --- | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | keygen | 0 | 5 | 224.595 ms | 378.849 ms |
| `rsa-pss-sha256` | artifact_sha256 | 1024 | 30 | 16.0 µs | 25.7 µs |
| `rsa-pss-sha256` | crypto_sign | 1024 | 30 | 2.354 ms | 3.370 ms |
| `rsa-pss-sha256` | crypto_verify | 1024 | 30 | 51.1 µs | 99.3 µs |
| `rsa-pss-sha256` | sign_end_to_end | 1024 | 30 | 125.050 ms | 148.820 ms |
| `rsa-pss-sha256` | verify_end_to_end | 1024 | 30 | 255.1 µs | 403.9 µs |
| `rsa-pss-sha256` | artifact_sha256 | 1048576 | 30 | 1.110 ms | 1.714 ms |
| `rsa-pss-sha256` | crypto_sign | 1048576 | 30 | 1.906 ms | 2.430 ms |
| `rsa-pss-sha256` | crypto_verify | 1048576 | 30 | 52.2 µs | 64.1 µs |
| `rsa-pss-sha256` | sign_end_to_end | 1048576 | 30 | 134.716 ms | 170.937 ms |
| `rsa-pss-sha256` | verify_end_to_end | 1048576 | 30 | 1.481 ms | 2.239 ms |
| `rsa-pss-sha256` | artifact_sha256 | 10485760 | 30 | 8.020 ms | 9.647 ms |
| `rsa-pss-sha256` | crypto_sign | 10485760 | 30 | 1.908 ms | 2.405 ms |
| `rsa-pss-sha256` | crypto_verify | 10485760 | 30 | 50.1 µs | 86.0 µs |
| `rsa-pss-sha256` | sign_end_to_end | 10485760 | 30 | 133.127 ms | 139.429 ms |
| `rsa-pss-sha256` | verify_end_to_end | 10485760 | 30 | 9.553 ms | 14.352 ms |
| `ecdsa-p256-sha256` | keygen | 0 | 5 | 68.4 µs | 305.1 µs |
| `ecdsa-p256-sha256` | artifact_sha256 | 1024 | 30 | 17.5 µs | 91.7 µs |
| `ecdsa-p256-sha256` | crypto_sign | 1024 | 30 | 33.0 µs | 41.4 µs |
| `ecdsa-p256-sha256` | crypto_verify | 1024 | 30 | 97.1 µs | 194.1 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 1024 | 30 | 1.769 ms | 3.319 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 1024 | 30 | 274.9 µs | 332.6 µs |
| `ecdsa-p256-sha256` | artifact_sha256 | 1048576 | 30 | 806.1 µs | 1.016 ms |
| `ecdsa-p256-sha256` | crypto_sign | 1048576 | 30 | 32.2 µs | 43.0 µs |
| `ecdsa-p256-sha256` | crypto_verify | 1048576 | 30 | 81.1 µs | 95.7 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 1048576 | 30 | 2.877 ms | 3.904 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 1048576 | 30 | 1.637 ms | 3.207 ms |
| `ecdsa-p256-sha256` | artifact_sha256 | 10485760 | 30 | 9.454 ms | 11.305 ms |
| `ecdsa-p256-sha256` | crypto_sign | 10485760 | 30 | 32.0 µs | 56.2 µs |
| `ecdsa-p256-sha256` | crypto_verify | 10485760 | 30 | 80.2 µs | 96.8 µs |
| `ecdsa-p256-sha256` | sign_end_to_end | 10485760 | 30 | 11.945 ms | 14.111 ms |
| `ecdsa-p256-sha256` | verify_end_to_end | 10485760 | 30 | 9.979 ms | 11.862 ms |
| `ed25519` | keygen | 0 | 5 | 46.4 µs | 123.7 µs |
| `ed25519` | artifact_sha256 | 1024 | 30 | 15.7 µs | 16.6 µs |
| `ed25519` | crypto_sign | 1024 | 30 | 34.6 µs | 50.4 µs |
| `ed25519` | crypto_verify | 1024 | 30 | 105.1 µs | 140.1 µs |
| `ed25519` | sign_end_to_end | 1024 | 30 | 2.178 ms | 3.995 ms |
| `ed25519` | verify_end_to_end | 1024 | 30 | 271.3 µs | 929.2 µs |
| `ed25519` | artifact_sha256 | 1048576 | 30 | 781.1 µs | 1.288 ms |
| `ed25519` | crypto_sign | 1048576 | 30 | 55.4 µs | 80.4 µs |
| `ed25519` | crypto_verify | 1048576 | 30 | 109.0 µs | 122.9 µs |
| `ed25519` | sign_end_to_end | 1048576 | 30 | 3.203 ms | 8.912 ms |
| `ed25519` | verify_end_to_end | 1048576 | 30 | 1.493 ms | 5.942 ms |
| `ed25519` | artifact_sha256 | 10485760 | 30 | 9.353 ms | 15.499 ms |
| `ed25519` | crypto_sign | 10485760 | 30 | 33.7 µs | 36.8 µs |
| `ed25519` | crypto_verify | 10485760 | 30 | 105.2 µs | 138.8 µs |
| `ed25519` | sign_end_to_end | 10485760 | 30 | 12.087 ms | 15.830 ms |
| `ed25519` | verify_end_to_end | 10485760 | 30 | 9.330 ms | 10.207 ms |

| Profile | Private key DER | Public key DER | Signature | Bundle (1 KiB artifact) |
| --- | ---: | ---: | ---: | ---: |
| `rsa-pss-sha256` | 1794 | 422 | 384 | 980 |
| `ecdsa-p256-sha256` | 138 | 91 | 64 | 560 |
| `ed25519` | 48 | 44 | 64 | 544 |
