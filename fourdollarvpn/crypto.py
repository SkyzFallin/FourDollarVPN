"""Local WireGuard key generation — client keys never touch the server."""

import base64
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair_local() -> tuple[str, str]:
    """Generate a WireGuard keypair locally using Curve25519.

    Returns (private_key_b64, public_key_b64) in WireGuard's base64 format.
    """
    private_key = X25519PrivateKey.generate()

    # WireGuard uses raw 32-byte Curve25519 keys, base64-encoded
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    private_b64 = base64.b64encode(private_bytes).decode()
    public_b64 = base64.b64encode(public_bytes).decode()

    return private_b64, public_b64


def generate_preshared_key() -> str:
    """Generate a WireGuard PreSharedKey (32 bytes random, base64).

    PSK adds a symmetric encryption layer on top of WireGuard's asymmetric
    crypto — defense-in-depth and post-quantum resistance for the PSK layer.
    """
    return base64.b64encode(os.urandom(32)).decode()
