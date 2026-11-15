# CI/CD integration evidence (C01-C05)

Copied from GitHub Actions; the files are unchanged except that ANSI colour codes were removed from
the logs. Secrets appear as `***` in the logs, as masked by GitHub Actions.

| Item | Value |
| --- | --- |
| Release pipeline run | <https://github.com/andi-frame/13523075_13523128_13523154_Tugas3_IF4020/actions/runs/43719510564> (success, commit `6f28fecccfb5`) |
| Publish image run | <https://github.com/andi-frame/13523075_13523128_13523154_Tugas3_IF4020/actions/runs/43719223274> (success, commit `3a6a7384df2c`) |
| Image | `docker.io/andiframe/zhongli@sha256:596ae4079fe1fad5e64f0428c3d2080ea792d818054035a06f11d15b894e4ff3` |
| Runner | GitHub-hosted `ubuntu-24.04` (Linux amd64), a new virtual machine for every job |

## Results

| ID | Profile | Case | Verify status | Exit | Deployment marker | Evidence |
| --- | --- | --- | --- | ---: | --- | --- |
| C01 | `rsa-pss-sha256` | valid release signed, verified, deployed | OK | 0 | present | `artifacts/verification-rsa-pss-sha256/`, `artifacts/deployment-marker-rsa-pss-sha256/` |
| C01 | `ecdsa-p256-sha256` | valid release signed, verified, deployed | OK | 0 | present | `artifacts/verification-ecdsa-p256-sha256/`, `artifacts/deployment-marker-ecdsa-p256-sha256/` |
| C01 | `ed25519` | valid release signed, verified, deployed | OK | 0 | present | `artifacts/verification-ed25519/`, `artifacts/deployment-marker-ed25519/` |
| C02 | `ecdsa-p256-sha256` | artifact-byte-changed (trust store `ci/trust.json`) | ARTIFACT_MISMATCH | 1 | absent | `artifacts/scenario-C02-artifact-byte-changed/` |
| C03 | `ecdsa-p256-sha256` | empty-trust-store (trust store `ci/scenarios/trust-empty.json`) | KEY_NOT_TRUSTED | 1 | absent | `artifacts/scenario-C03-empty-trust-store/` |
| C03 | `ecdsa-p256-sha256` | key-not-allowed-for-package (trust store `ci/scenarios/trust-other-package.json`) | KEY_NOT_TRUSTED | 1 | absent | `artifacts/scenario-C03-key-not-allowed-for-package/` |
| C04 | `ecdsa-p256-sha256` | artifact-missing (trust store `ci/trust.json`) | INPUT_ERROR | 2 | absent | `artifacts/scenario-C04-artifact-missing/` |
| C05 | `ed25519` | CLI as runner 1001:1001, no TTY, `--network none` | - | 0 / 2 | - | `artifacts/runtime-contract/runtime-result.txt` |

C01 deployment markers record the SHA-256 of the deployed bytes, which the deploy job compares with
the SHA-256 written by the verify job. In C02-C04 the protected deploy step runs only if the captured
exit code is 0; each job then checks the original exit code, the status, `valid = false` and that no
marker exists (`scenario-result.txt`). C05 also checks that a missing `--out` fails with exit 2 instead
of prompting, and that every output file is owned by the runner UID/GID.

## Files

- `run.json`: run URLs, commit, conclusion and the URL of every job.
- `artifacts/`: everything the jobs uploaded (`gh run download`): the built artifact, the three bundles,
  verification JSON, deployment markers, and per-scenario exit code, JSON, stderr and result.
- `logs/`: one log per job of the release pipeline; `publish-logs/`: the image build and push.
