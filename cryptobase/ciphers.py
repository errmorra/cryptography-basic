"""Collection of classic and simple modern cipher implementations.

Every cipher exposes two functions with a consistent signature::

    encode(text, ...) -> str
    decode(text, ...) -> str

The functions are pure (no I/O) so they are easy to test and reuse.
"""

from __future__ import annotations

import base64 as _base64
import string

ALPHABET = string.ascii_lowercase
ALPHABET_SIZE = len(ALPHABET)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _shift_char(char: str, shift: int) -> str:
    """Shift a single character by ``shift`` positions, preserving case.

    Non-alphabetic characters are returned unchanged.
    """
    if char.isupper():
        base = ord("A")
        return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
    if char.islower():
        base = ord("a")
        return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
    return char


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _mod_inverse(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no modular inverse modulo {m}")
    return x % m


# ---------------------------------------------------------------------------
# Caesar cipher
# ---------------------------------------------------------------------------
def caesar_encode(text: str, key: int = 3) -> str:
    """Shift every letter forward by ``key`` positions (case preserved)."""
    shift = key % ALPHABET_SIZE
    return "".join(_shift_char(c, shift) for c in text)


def caesar_decode(text: str, key: int = 3) -> str:
    """Reverse :func:`caesar_encode`."""
    return caesar_encode(text, -key)


# ---------------------------------------------------------------------------
# ROT13 (Caesar with a fixed key of 13, self-inverse)
# ---------------------------------------------------------------------------
def rot13_encode(text: str) -> str:
    return caesar_encode(text, 13)


def rot13_decode(text: str) -> str:
    return caesar_encode(text, 13)


# ---------------------------------------------------------------------------
# Atbash (mirror the alphabet, self-inverse)
# ---------------------------------------------------------------------------
def atbash_encode(text: str) -> str:
    result = []
    for c in text:
        if c.isupper():
            result.append(chr(ord("Z") - (ord(c) - ord("A"))))
        elif c.islower():
            result.append(chr(ord("z") - (ord(c) - ord("a"))))
        else:
            result.append(c)
    return "".join(result)


def atbash_decode(text: str) -> str:
    return atbash_encode(text)


# ---------------------------------------------------------------------------
# Vigenere cipher
# ---------------------------------------------------------------------------
def _vigenere(text: str, key: str, sign: int) -> str:
    if not key or not any(c.isalpha() for c in key):
        raise ValueError("Vigenere key must contain at least one letter")

    key = [ord(k.lower()) - ord("a") for k in key if k.isalpha()]
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = sign * key[ki % len(key)]
            result.append(_shift_char(c, shift))
            ki += 1
        else:
            result.append(c)
    return "".join(result)


def vigenere_encode(text: str, key: str) -> str:
    return _vigenere(text, key, 1)


def vigenere_decode(text: str, key: str) -> str:
    return _vigenere(text, key, -1)


# ---------------------------------------------------------------------------
# Affine cipher: E(x) = (a*x + b) mod 26
# ---------------------------------------------------------------------------
def affine_encode(text: str, a: int = 5, b: int = 8) -> str:
    _mod_inverse(a, ALPHABET_SIZE)  # validate ``a`` is coprime with 26
    result = []
    for c in text:
        if c.isupper():
            x = ord(c) - ord("A")
            result.append(chr((a * x + b) % ALPHABET_SIZE + ord("A")))
        elif c.islower():
            x = ord(c) - ord("a")
            result.append(chr((a * x + b) % ALPHABET_SIZE + ord("a")))
        else:
            result.append(c)
    return "".join(result)


def affine_decode(text: str, a: int = 5, b: int = 8) -> str:
    a_inv = _mod_inverse(a, ALPHABET_SIZE)
    result = []
    for c in text:
        if c.isupper():
            y = ord(c) - ord("A")
            result.append(chr(a_inv * (y - b) % ALPHABET_SIZE + ord("A")))
        elif c.islower():
            y = ord(c) - ord("a")
            result.append(chr(a_inv * (y - b) % ALPHABET_SIZE + ord("a")))
        else:
            result.append(c)
    return "".join(result)


# ---------------------------------------------------------------------------
# XOR cipher (works on arbitrary bytes, output is hex so it stays printable)
# ---------------------------------------------------------------------------
def xor_encode(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key must not be empty")
    key_bytes = key.encode("utf-8")
    data = text.encode("utf-8")
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return out.hex()


def xor_decode(text: str, key: str) -> str:
    if not key:
        raise ValueError("XOR key must not be empty")
    key_bytes = key.encode("utf-8")
    try:
        data = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("XOR ciphertext must be valid hex") from exc
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return out.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Base64 (an encoding rather than a cipher, but handy and commonly requested)
# ---------------------------------------------------------------------------
def base64_encode(text: str) -> str:
    return _base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(text: str) -> str:
    try:
        return _base64.b64decode(text.encode("ascii")).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - surface a friendly error
        raise ValueError("Invalid Base64 input") from exc


# ---------------------------------------------------------------------------
# Registry used by the CLI and high-level API
# ---------------------------------------------------------------------------
CIPHERS = {
    "caesar": {
        "encode": caesar_encode,
        "decode": caesar_decode,
        "help": "Caesar shift cipher (default key=3).",
    },
    "rot13": {
        "encode": rot13_encode,
        "decode": rot13_decode,
        "help": "ROT13, a self-inverse Caesar shift of 13.",
    },
    "atbash": {
        "encode": atbash_encode,
        "decode": atbash_decode,
        "help": "Atbash mirror cipher (self-inverse).",
    },
    "vigenere": {
        "encode": vigenere_encode,
        "decode": vigenere_decode,
        "help": "Vigenere polyalphabetic cipher (requires --key).",
    },
    "affine": {
        "encode": affine_encode,
        "decode": affine_decode,
        "help": "Affine cipher E(x)=(a*x+b) mod 26 (defaults a=5, b=8).",
    },
    "xor": {
        "encode": xor_encode,
        "decode": xor_decode,
        "help": "Repeating-key XOR cipher, output as hex (requires --key).",
    },
    "base64": {
        "encode": base64_encode,
        "decode": base64_decode,
        "help": "Base64 encoding/decoding.",
    },
}


def list_ciphers() -> list[str]:
    """Return the available cipher names."""
    return sorted(CIPHERS)
