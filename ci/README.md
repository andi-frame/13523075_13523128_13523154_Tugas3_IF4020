# CI configuration (trusted inputs)

- `pipeline.env`: image reference pinned by digest and release metadata.
- `trust.json`: trust store for the demo pipeline, prepared before any run
  from the public keys in `keys/`. The pipeline never adds keys to it.
- `keys/*.pub.pem`: public halves of the CI demo signing keys. They were
  generated only for this demo. The private halves exist solely as the
  repository secrets `SIGNING_KEY_ED25519`, `SIGNING_KEY_RSA_PSS_SHA256` and
  `SIGNING_KEY_ECDSA_P256_SHA256` and are never committed.

To rotate a key: `keygen` locally, `trust add --key keys/<new>.pub.pem
--package contoh-app --store ci/trust.json`, `trust remove` the old keyid,
update the secret, and commit the reviewed change.
