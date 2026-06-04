"""Command-line interface for cryptobase.

Examples
--------
Encode with Caesar (default key 3)::

    python -m cryptobase encode caesar "Hello World"

Decode a Vigenere message::

    python -m cryptobase decode vigenere "Rijvs Uyvjn" --key lemon

Read from stdin and write to stdout::

    echo "secret" | python -m cryptobase encode rot13
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .ciphers import CIPHERS, list_ciphers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptobase",
        description="Encode or decode text with a variety of ciphers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="action", required=True)

    cipher_help = "\n".join(f"  {name}: {meta['help']}" for name, meta in sorted(CIPHERS.items()))

    for action in ("encode", "decode"):
        p = sub.add_parser(
            action,
            help=f"{action.capitalize()} text.",
            description=f"{action.capitalize()} text.\n\nAvailable ciphers:\n{cipher_help}",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        p.add_argument("cipher", choices=list_ciphers(), help="Cipher to use.")
        p.add_argument(
            "text",
            nargs="?",
            help="Text to process. If omitted, text is read from stdin.",
        )
        p.add_argument("--key", help="Key/passphrase (Vigenere, XOR).")
        p.add_argument("-k", "--shift", type=int, help="Numeric key for Caesar (default 3).")
        p.add_argument("-a", type=int, help="Affine multiplier 'a' (default 5).")
        p.add_argument("-b", type=int, help="Affine offset 'b' (default 8).")

    return parser


def _collect_params(args: argparse.Namespace) -> dict:
    """Map CLI flags onto the keyword arguments each cipher expects."""
    cipher = args.cipher
    params: dict = {}

    if cipher == "caesar":
        if args.shift is not None:
            params["key"] = args.shift
    elif cipher in ("vigenere", "xor"):
        if not args.key:
            raise SystemExit(f"error: cipher '{cipher}' requires --key")
        params["key"] = args.key
    elif cipher == "affine":
        if args.a is not None:
            params["a"] = args.a
        if args.b is not None:
            params["b"] = args.b

    return params


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    text = args.text
    if text is None:
        text = sys.stdin.read().rstrip("\n")

    func = CIPHERS[args.cipher][args.action]
    params = _collect_params(args)

    try:
        result = func(text, **params)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
