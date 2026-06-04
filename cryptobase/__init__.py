"""cryptobase: a small collection of classic ciphers with encode/decode.

Quick start::

    from cryptobase import encode, decode

    secret = encode("caesar", "Hello", key=3)
    plain = decode("caesar", secret, key=3)

The original ``base_encrypt`` / ``base_decrypt`` helpers are kept for
backwards compatibility with the very first version of this project.
"""

from __future__ import annotations

from .ciphers import CIPHERS, caesar_decode, caesar_encode, list_ciphers

__version__ = "1.0.0"

__all__ = [
    "encode",
    "decode",
    "list_ciphers",
    "base_encrypt",
    "base_decrypt",
    "CIPHERS",
]


def _resolve(cipher: str, action: str):
    cipher = cipher.lower()
    if cipher not in CIPHERS:
        available = ", ".join(list_ciphers())
        raise ValueError(f"Unknown cipher {cipher!r}. Available: {available}")
    return CIPHERS[cipher][action]


def encode(cipher: str, text: str, **params) -> str:
    """Encode ``text`` using the named ``cipher``.

    Extra keyword arguments (e.g. ``key``, ``a``, ``b``) are passed straight
    through to the underlying cipher implementation.
    """
    return _resolve(cipher, "encode")(text, **params)


def decode(cipher: str, text: str, **params) -> str:
    """Decode ``text`` using the named ``cipher``."""
    return _resolve(cipher, "decode")(text, **params)


# -- Backwards-compatible helpers -------------------------------------------
def base_encrypt(message: str, key: int) -> str:
    """Legacy Caesar encrypt (lowercases input, as the original did)."""
    return caesar_encode(message.lower(), key)


def base_decrypt(encrypted_message: str, key: int) -> str:
    """Legacy Caesar decrypt."""
    return caesar_decode(encrypted_message, key)
