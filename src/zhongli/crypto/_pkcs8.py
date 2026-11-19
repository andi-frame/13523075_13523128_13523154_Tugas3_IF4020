"""Validate a PKCS#8 envelope while allowing standard optional metadata.

The cryptography backend validates the private key itself. This check distinguishes
PKCS#8 from SEC1/PKCS#1 and checks the profile's AlgorithmIdentifier; it does not
require optional attributes to survive a backend re-export.
"""


def _value(data: bytes, offset: int) -> tuple[int, bytes, int]:
    start = offset
    if offset >= len(data):
        raise ValueError("Truncated DER value")
    tag = data[offset]
    offset += 1
    if tag & 0x1f == 0x1f:
        while offset < len(data) and data[offset] & 0x80:
            offset += 1
        offset += 1
    if offset >= len(data):
        raise ValueError("Missing DER length")
    size = data[offset]
    offset += 1
    if size & 0x80:
        count = size & 0x7f
        if not count or offset + count > len(data) or data[offset] == 0:
            raise ValueError("Invalid DER length")
        size = int.from_bytes(data[offset:offset + count], "big")
        offset += count
        if size < 128:
            raise ValueError("Non-minimal DER length")
    end = offset + size
    if end > len(data) or end <= start:
        raise ValueError("Truncated DER content")
    return tag, data[offset:end], end


def _fields(data: bytes) -> list[tuple[int, bytes]]:
    fields, offset = [], 0
    while offset < len(data):
        tag, content, offset = _value(data, offset)
        fields.append((tag, content))
    return fields


def _private_key_info(der: bytes) -> list[tuple[int, bytes]]:
    tag, content, end = _value(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("Expected one PKCS8 sequence without trailing data")
    fields = _fields(content)
    if len(fields) < 3 or fields[0] not in ((2, b"\x00"), (2, b"\x01")) \
            or fields[1][0] != 0x30 or fields[2][0] != 4:
        raise ValueError("Expected PKCS8 version, algorithm and private key")
    optional = fields[3:]
    if optional and optional[0][0] == 0xa0:
        for tag, attribute in _fields(optional.pop(0)[1]):
            parts = _fields(attribute)
            if tag != 0x30 or len(parts) != 2 or parts[0][0] != 6 or parts[1][0] != 0x31 \
                    or not _fields(parts[1][1]):
                raise ValueError("Invalid PKCS8 attribute")
    has_public_key = len(optional) == 1 and optional[0][0] == 0x81
    if optional and not has_public_key:
        raise ValueError("Unexpected PKCS8 field")
    if (fields[0][1] == b"\x01") != has_public_key:
        raise ValueError("PKCS8 version does not match optional public key")
    return fields


def validate_pkcs8(der: bytes, exported_der: bytes) -> None:
    """Check the envelope and match its algorithm to the validated backend key.

    Standard optional attributes are accepted. DER lengths, trailing data,
    algorithm OIDs and parameters remain checked. Private key material is
    validated by the backend before calling this function.
    """
    original = _private_key_info(der)
    expected = _private_key_info(exported_der)
    if original[1] != expected[1]:
        raise ValueError("PKCS8 algorithm or parameters do not match the profile")
