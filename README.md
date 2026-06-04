# cryptobase

A small, dependency-free toolkit of classic ciphers with full **encode** and
**decode** support, usable both as a Python library and a command-line tool.

It started life as a single-file Caesar cipher and has grown into a tidy
package with several ciphers, a CLI, and a test suite.

## Features

| Cipher    | Key / options          | Notes                                   |
|-----------|------------------------|-----------------------------------------|
| `caesar`  | `--shift` (int, def 3) | Classic shift cipher, case preserved.   |
| `rot13`   | none                   | Caesar with shift 13, self-inverse.     |
| `atbash`  | none                   | Mirrors the alphabet, self-inverse.     |
| `vigenere`| `--key` (word)         | Polyalphabetic cipher.                  |
| `affine`  | `-a`, `-b` (ints)      | `E(x) = (a*x + b) mod 26`, `a` coprime 26. |
| `xor`     | `--key` (word)         | Repeating-key XOR, output as hex.       |
| `base64`  | none                   | Standard Base64 encode/decode.          |

Every cipher supports both directions, so decoding is always available.

## Requirements

- Python 3.9+
- No runtime dependencies (standard library only)
- `pytest` is only needed to run the tests

## Installation

Clone the repo and (optionally) install it in editable mode:

```bash
git clone https://github.com/errmorra/cryptography-basic
cd cryptography-basic
pip install -e .
```

You can also just run it straight from the source tree with `python -m cryptobase`.

## Command-line usage

```bash
# Encode with Caesar (default key 3)
python -m cryptobase encode caesar "Hello World"
# -> Khoor Zruog

# Decode it back with a custom shift
python -m cryptobase encode caesar "Hello World" --shift 5   # Mjqqt Btwqi
python -m cryptobase decode caesar "Mjqqt Btwqi" --shift 5   # Hello World

# Vigenere needs a key
python -m cryptobase encode vigenere "attack at dawn" --key lemon
python -m cryptobase decode vigenere "lxfopv ef rnhr" --key lemon

# Affine with custom a/b
python -m cryptobase encode affine "hello" -a 7 -b 3

# XOR (output is hex so it stays printable)
python -m cryptobase encode xor "secret" --key passphrase

# Base64
python -m cryptobase encode base64 "hello"

# Read from stdin when no text argument is given
echo "pipe me" | python -m cryptobase encode rot13
```

If you install the package, a `cryptobase` console script is available too:

```bash
cryptobase encode rot13 "Hello"
```

## Library usage

```python
import cryptobase as cb

secret = cb.encode("vigenere", "attack at dawn", key="lemon")
plain = cb.decode("vigenere", secret, key="lemon")

print(cb.list_ciphers())  # ['affine', 'atbash', 'base64', 'caesar', ...]
```

The lower-level functions live in `cryptobase.ciphers` if you prefer calling
them directly (e.g. `caesar_encode`, `vigenere_decode`).

## Running the tests

```bash
pip install pytest
python -m pytest
```

## Note on security

These are educational/classic ciphers. They are great for learning and puzzles
but are **not** secure for protecting real secrets. For real-world needs use a
vetted library such as [`cryptography`](https://cryptography.io/).
