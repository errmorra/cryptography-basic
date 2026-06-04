import io

import pytest

from cryptobase.cli import main


def test_encode_decode_caesar(capsys):
    assert main(["encode", "caesar", "abc", "--shift", "3"]) == 0
    out = capsys.readouterr().out.strip()
    assert out == "def"

    assert main(["decode", "caesar", "def", "--shift", "3"]) == 0
    out = capsys.readouterr().out.strip()
    assert out == "abc"


def test_default_caesar_key(capsys):
    assert main(["encode", "caesar", "abc"]) == 0
    assert capsys.readouterr().out.strip() == "def"


def test_vigenere_requires_key():
    with pytest.raises(SystemExit):
        main(["encode", "vigenere", "hello"])


def test_rot13_roundtrip(capsys):
    main(["encode", "rot13", "Hello"])
    encoded = capsys.readouterr().out.strip()
    main(["decode", "rot13", encoded])
    assert capsys.readouterr().out.strip() == "Hello"


def test_reads_from_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("secret\n"))
    assert main(["encode", "rot13"]) == 0
    assert capsys.readouterr().out.strip() == "frperg"


def test_xor_roundtrip(capsys):
    main(["encode", "xor", "Hello", "--key", "k"])
    encoded = capsys.readouterr().out.strip()
    main(["decode", "xor", encoded, "--key", "k"])
    assert capsys.readouterr().out.strip() == "Hello"


def test_invalid_base64_returns_error_code(capsys):
    rc = main(["decode", "base64", "!!!notbase64!!!"])
    assert rc == 1
    assert "error" in capsys.readouterr().err.lower()
