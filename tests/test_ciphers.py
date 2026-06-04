import pytest

import cryptobase as cb
from cryptobase import ciphers


SAMPLE = "Thank you for testing my code!"


@pytest.mark.parametrize(
    "cipher, params",
    [
        ("caesar", {"key": 3}),
        ("caesar", {"key": 0}),
        ("caesar", {"key": 29}),
        ("rot13", {}),
        ("atbash", {}),
        ("vigenere", {"key": "lemon"}),
        ("affine", {"a": 5, "b": 8}),
        ("affine", {"a": 7, "b": 3}),
        ("xor", {"key": "swordfish"}),
        ("base64", {}),
    ],
)
def test_roundtrip(cipher, params):
    encoded = cb.encode(cipher, SAMPLE, **params)
    decoded = cb.decode(cipher, encoded, **params)
    assert decoded == SAMPLE


def test_caesar_known_value():
    assert ciphers.caesar_encode("abc", 3) == "def"
    assert ciphers.caesar_decode("def", 3) == "abc"


def test_caesar_preserves_case_and_symbols():
    assert ciphers.caesar_encode("Hello, World!", 3) == "Khoor, Zruog!"


def test_rot13_self_inverse():
    assert ciphers.rot13_encode("Hello") == "Uryyb"
    assert ciphers.rot13_encode(ciphers.rot13_encode("Hello")) == "Hello"


def test_atbash_known_value():
    assert ciphers.atbash_encode("abc") == "zyx"
    assert ciphers.atbash_encode("Hello") == "Svool"


def test_vigenere_known_value():
    assert ciphers.vigenere_encode("attackatdawn", "lemon") == "lxfopvefrnhr"
    assert ciphers.vigenere_decode("lxfopvefrnhr", "lemon") == "attackatdawn"


def test_affine_invalid_a_raises():
    with pytest.raises(ValueError):
        ciphers.affine_encode("hello", a=2, b=1)  # 2 not coprime with 26


def test_vigenere_empty_key_raises():
    with pytest.raises(ValueError):
        ciphers.vigenere_encode("hello", "")


def test_xor_requires_key():
    with pytest.raises(ValueError):
        ciphers.xor_encode("hello", "")


def test_xor_bad_hex_raises():
    with pytest.raises(ValueError):
        ciphers.xor_decode("not-hex", "key")


def test_base64_invalid_raises():
    with pytest.raises(ValueError):
        ciphers.base64_decode("!!!notbase64!!!")


def test_unknown_cipher_raises():
    with pytest.raises(ValueError):
        cb.encode("nope", "data")


def test_list_ciphers():
    names = cb.list_ciphers()
    assert "caesar" in names
    assert "vigenere" in names
    assert names == sorted(names)


def test_backwards_compatible_helpers():
    enc = cb.base_encrypt("Hello", 3)
    assert cb.base_decrypt(enc, 3) == "hello"
