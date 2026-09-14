import base64
import re


# ============================================================
# Safe Text Validation
#
# A03: Injection
# A04: Insecure Design
# ============================================================

def clean_text(value, max_length=1000):
    """ 
    Normalize and validate a text value.

    This function does not replace Jinja autoescaping.
    It is an additional server-side input validation layer.
    """

    if not isinstance(value, str):
        return ""

    value = value.replace("\x00", "")
    value = value.strip()

    return value[:max_length]


def is_safe_identifier(value, min_length=1, max_length=100):
    """
    Validate a simple identifier.

    Only letters, numbers, underscore, hyphen and dot are accepted.
    """

    if not isinstance(value, str):
        return False

    if not min_length <= len(value) <= max_length:
        return False

    return bool(
        re.fullmatch(
            r"[A-Za-z0-9_.-]+",
            value,
        )
    )


# ============================================================
# Base64 Encoding / Decoding
#
# IMPORTANT:
# Base64 is encoding, NOT encryption.
# It must never be used as a replacement for AES encryption.
#
# A02: Cryptographic Failures
# ============================================================

def encode_base64(value):
    """
    Encode bytes into an ASCII Base64 string.
    """

    if not isinstance(value, bytes):
        raise TypeError(
            "Value must be bytes."
        )

    return base64.b64encode(value).decode("ascii")


def decode_base64(value):
    """
    Decode a Base64 string into bytes.

    Invalid Base64 data is rejected instead of silently ignored.
    """

    if not isinstance(value, str):
        raise TypeError(
            "Base64 value must be a string."
        )

    try:
        return base64.b64decode(
            value,
            validate=True,
        )
    except Exception as exc:
        raise ValueError(
            "Invalid Base64 data."
        ) from exc


# ============================================================
# Filename Validation
#
# A01: Broken Access Control / Path Traversal
# ============================================================

def validate_filename(filename):
    """
    Validate a user-supplied display filename.

    The returned filename is for metadata/display only.
    It must never be used directly as a storage path.
    """

    if not isinstance(filename, str):
        return False

    filename = filename.strip()

    if not filename or len(filename) > 255:
        return False

    # Reject path separators and traversal patterns.
    if "/" in filename or "\\" in filename:
        return False

    if ".." in filename:
        return False

    # Reject control characters.
    if any(ord(character) < 32 for character in filename):
        return False

    return True


# ============================================================
# SHA-256 Format Validation
#
# A08: Software and Data Integrity Failures
# ============================================================

def is_valid_sha256(value):
    """
    Validate the format of a SHA-256 hexadecimal digest.
    """

    if not isinstance(value, str):
        return False

    if len(value) != 64:
        return False

    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{64}",
            value,
        )
    )
