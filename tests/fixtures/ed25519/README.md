Public **test-only** fixtures. Never use the TEST_ONLY key pair for real releases
or add its fingerprint to a production trust store.

- `demo.bin`: the same fixed bytes as `../rsa/demo.bin` (NUL, non-UTF-8 bytes, CRLF).
- `manifest.json`: canonical manifest, no trailing newline; package `demo`, version `1.0`.
- `bundle.json`: valid pure Ed25519 signature over those manifest bytes.
- `trust.json`: trust store that allows the public key for package `demo`.

Ed25519 signatures are deterministic, so regenerating the bundle with the same
key and manifest reproduces the same signature.
