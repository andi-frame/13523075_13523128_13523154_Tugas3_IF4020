"""Algorithm adapters for signing original manifest bytes.

Each profile has one adapter module: `zhongli.crypto.rsa`,
`zhongli.crypto.ecdsa` and `zhongli.crypto.ed25519`. All three export the
same functions, so `zhongli.keys` can route a key to its adapter and the
signer and verifier never branch on the algorithm. Each adapter raises its own
``KeyValidationError`` (a ``ValueError``) when a key violates its profile.

| Function | Parameters | Returns |
| --- | --- | --- |
| ``generate_keypair(profile)`` | profile name | ``KeyPair`` with ``private_key`` and ``public_key`` |
| ``load_private_key(pem_bytes)`` | PKCS#8 PEM ``bytes`` | private key object |
| ``load_public_key(pem_bytes)`` | SPKI PEM ``bytes`` | public key object |
| ``export_private_pkcs8_pem(key)`` / ``_der`` | private key | ``bytes`` |
| ``export_public_spki_pem(key)`` / ``_der`` | public key | ``bytes`` |
| ``public_from_private(key)`` | private key | public key |
| ``profile_of(key)`` | private or public key | profile name ``str`` |
| ``fingerprint(public_key)`` | public key | keyid, 64 lowercase hex ``str`` |
| ``sign_bytes(private_key, manifest_bytes)`` | key, message ``bytes`` | raw signature ``bytes`` |
| ``verify_bytes(public_key, manifest_bytes, signature_bytes)`` | key, message, signature | ``bool``, never raises |

The message is always the exact manifest bytes from the bundle. RSA-PSS and
ECDSA hash it once with SHA-256 inside the library; nothing is pre-hashed.

| Profile | Library call | Signature |
| --- | --- | --- |
| ``rsa-pss-sha256`` | ``sign(M, PSS(mgf=MGF1(SHA256()), salt_length=32), SHA256())`` | 384 bytes |
| ``ecdsa-p256-sha256`` | ``sign(M, ECDSA(SHA256(), deterministic_signing=True))`` | 64 bytes ``r ‖ s`` |
| ``ed25519`` | ``sign(M)`` (pure Ed25519) | 64 bytes |
"""
