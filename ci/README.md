# CI configuration (trusted inputs)

- `pipeline.env`: image reference pinned by digest and release metadata.
- `trust.json`: trust store for the demo pipeline, prepared before any run
  from the public keys in `keys/`. The pipeline never adds keys to it.
- `scenarios/trust-empty.json`: empty trust store for scenario C03.
- `scenarios/trust-other-package.json`: the same three CI keys, allowed only for
  `other-app`, for scenario C03.
- `keys/*.pub.pem`: public halves of the CI demo signing keys. They were
  generated only for this demo. The private halves exist solely as the
  repository secrets `SIGNING_KEY_ED25519`, `SIGNING_KEY_RSA_PSS_SHA256` and
  `SIGNING_KEY_ECDSA_P256_SHA256` and are never committed.

| Key file | Profile | Keyid |
| --- | --- | --- |
| `keys/ci-ed25519.pub.pem` | `ed25519` | `351bda0b8320fc4deaa5479349546f550c917c1b2f2e100d6287d4bd1c2faa7c` |
| `keys/ci-rsa-pss-sha256.pub.pem` | `rsa-pss-sha256` | `a8f599b03f91e26d62cfdc8ae1aa9014c634df9f3e418c475fb7fac5725b9d07` |
| `keys/ci-ecdsa-p256-sha256.pub.pem` | `ecdsa-p256-sha256` | `6aa00f55fff2e931faa11e25df670d9482bf6f2ba0ec6a6e3a7b82913de20d56` |

To rotate a key: `keygen` locally, `trust add --key keys/<new>.pub.pem
--package contoh-app --store ci/trust.json` (and `--package other-app --store
ci/scenarios/trust-other-package.json`), `trust remove` the old keyid, update the
secret, and commit the reviewed change.
