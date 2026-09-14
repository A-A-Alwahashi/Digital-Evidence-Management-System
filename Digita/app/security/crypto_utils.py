import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from flask import current_app


# ============================================================
# AES-GCM Encryption
# ============================================================

def _get_aes_key():
    """
    Load the AES key from the environment configuration.

    The key is never hard-coded in the source code.

    A02: Cryptographic Failures
    """

    encoded_key = current_app.config.get("AES_KEY")

    if not encoded_key:
        raise RuntimeError("AES_KEY is not configured.")

    try:
        key = base64.b64decode(
            encoded_key,
            validate=True,
        )
    except Exception as exc:
        raise RuntimeError(
            "AES_KEY is not valid Base64."
        ) from exc

    # AES-256 requires exactly 32 bytes.
    if len(key) != 32:
        raise RuntimeError(
            "AES_KEY must decode to exactly 32 bytes."
        )

    return key


def encrypt_evidence(file_bytes):
    """
    Encrypt evidence using AES-256-GCM.

    AES-GCM provides:
    - Confidentiality
    - Integrity
    - Authentication tag

    A02: Cryptographic Failures
    A08: Software and Data Integrity Failures

    Returns:
        encrypted_data: ciphertext + authentication tag
        nonce: Base64 encoded nonce
    """

    if not isinstance(file_bytes, bytes):
        raise TypeError(
            "Evidence must be provided as bytes."
        )

    if not file_bytes:
        raise ValueError(
            "Evidence cannot be empty."
        )

    key = _get_aes_key()

    # 96-bit nonce is the standard recommended nonce size for GCM.
    nonce = os.urandom(12)

    aes_gcm = AESGCM(key)

    encrypted_data = aes_gcm.encrypt(
        nonce,
        file_bytes,
        None,
    )

    return (
        encrypted_data,
        base64.b64encode(nonce).decode("ascii"),
    )


def decrypt_evidence(encrypted_data, encoded_nonce):
    """
    Decrypt AES-GCM encrypted evidence.

    AES-GCM automatically verifies the authentication tag.
    If the encrypted data or nonce was modified, decryption fails.

    A02: Cryptographic Failures
    A08: Software and Data Integrity Failures
    """

    if not isinstance(encrypted_data, bytes):
        raise TypeError(
            "Encrypted evidence must be bytes."
        )

    if not encrypted_data:
        raise ValueError(
            "Encrypted evidence cannot be empty."
        )

    if not isinstance(encoded_nonce, str):
        raise TypeError(
            "Nonce must be a Base64 string."
        )

    try:
        nonce = base64.b64decode(
            encoded_nonce,
            validate=True,
        )
    except Exception as exc:
        raise ValueError(
            "Invalid encryption nonce."
        ) from exc

    if len(nonce) != 12:
        raise ValueError(
            "Invalid AES-GCM nonce length."
        )

    key = _get_aes_key()

    aes_gcm = AESGCM(key)

    # Invalid authentication tag raises an exception.
    return aes_gcm.decrypt(
        nonce,
        encrypted_data,
        None,
    )


# ============================================================
# RSA Private Key
# ============================================================

def _load_private_key():
    """
    Load the RSA private key from the configured file.

    The private key must remain server-side and must never be sent
    to the client.

    A02: Cryptographic Failures
    """

    private_key_path = current_app.config[
        "PRIVATE_KEY_PATH"
    ]

    if not os.path.isfile(private_key_path):
        raise RuntimeError(
            "RSA private key file was not found."
        )

    with open(
        private_key_path,
        "rb",
    ) as key_file:
        private_key_data = key_file.read()

    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
    )

    return private_key


# ============================================================
# RSA Public Key
# ============================================================

def _load_public_key():
    """
    Load the RSA public key from the configured file.

    The public key is used only for signature verification.
    """

    public_key_path = current_app.config[
        "PUBLIC_KEY_PATH"
    ]

    if not os.path.isfile(public_key_path):
        raise RuntimeError(
            "RSA public key file was not found."
        )

    with open(
        public_key_path,
        "rb",
    ) as key_file:
        public_key_data = key_file.read()

    public_key = serialization.load_pem_public_key(
        public_key_data,
    )

    return public_key


# ============================================================
# RSA Digital Signature
# ============================================================

def sign_hash(sha256_hash):
    """
    Sign a SHA-256 hash using the RSA private key.

    RSA-PSS is used because it provides a modern probabilistic
    digital signature scheme.

    A08: Software and Data Integrity Failures
    """

    if not isinstance(sha256_hash, str):
        raise TypeError(
            "SHA-256 hash must be a string."
        )

    if len(sha256_hash) != 64:
        raise ValueError(
            "Invalid SHA-256 hash length."
        )

    try:
        # Ensure the supplied value is actually hexadecimal.
        bytes.fromhex(sha256_hash)
    except ValueError as exc:
        raise ValueError(
            "Invalid SHA-256 hash format."
        ) from exc

    private_key = _load_private_key()

    hash_bytes = sha256_hash.encode("ascii")

    signature = private_key.sign(
        hash_bytes,
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(
        signature
    ).decode("ascii")


# ============================================================
# RSA Signature Verification
# ============================================================

def verify_signature(sha256_hash, encoded_signature):
    """
    Verify an RSA-PSS digital signature.

    Returns:
        True  -> signature is valid
        False -> signature is invalid

    A08: Software and Data Integrity Failures
    """

    if not isinstance(sha256_hash, str):
        return False

    if not isinstance(encoded_signature, str):
        return False

    if len(sha256_hash) != 64:
        return False

    try:
        bytes.fromhex(sha256_hash)
    except ValueError:
        return False

    try:
        signature = base64.b64decode(
            encoded_signature,
            validate=True,
        )
    except Exception:
        return False

    public_key = _load_public_key()

    hash_bytes = sha256_hash.encode("ascii")

    try:
        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return True

    except Exception:
        return False
