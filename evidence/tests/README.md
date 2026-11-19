# Release regression checks

- `pytest.txt`: `uv run pytest -q` on version 0.1.1; 308 tests pass, none skipped.
- `container-regressions.json`: additional checks against the published image by digest,
  with no network, no TTY and the host UID/GID. A compact trust store below 1 MiB is
  expanded by `trust add` to more than 1 MiB; `trust list` and verification of the
  Ed25519 fixture still succeed. A SEC1 ECDSA private key rewrapped as `PRIVATE KEY`
  is rejected by `sign` with exit 2 and creates no bundle.

The same regression inputs are constructed by
`tests/test_trust.py::test_large_store_stays_usable_after_add` and
`tests/test_ecdsa.py::test_reject_sec1_disguised_as_pkcs8`. To repeat locally:

```sh
uv run pytest -q tests/test_trust.py tests/test_ecdsa.py
```

All keys used for these checks come from the intentional test fixtures, not CI secrets.
