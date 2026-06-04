import argparse
import base64
import binascii
import string

LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase


def _shift_char(char: str, shift: int) -> str:
    if char in LOWERCASE:
        index = LOWERCASE.index(char)
        return LOWERCASE[(index + shift) % 26]
    if char in UPPERCASE:
        index = UPPERCASE.index(char)
        return UPPERCASE[(index + shift) % 26]
    return char


def caesar_encrypt(message: str, key: int) -> str:
    shift = key % 26
    return "".join(_shift_char(char, shift) for char in message)


def caesar_decrypt(message: str, key: int) -> str:
    return caesar_encrypt(message, -key)


def rot13_transform(message: str) -> str:
    return caesar_encrypt(message, 13)


def vigenere_encrypt(message: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be alphabetic.")

    key_shifts = [LOWERCASE.index(char.lower()) for char in key]
    output = []
    key_index = 0

    for char in message:
        if char.isalpha():
            shift = key_shifts[key_index % len(key_shifts)]
            output.append(_shift_char(char, shift))
            key_index += 1
        else:
            output.append(char)

    return "".join(output)


def vigenere_decrypt(message: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be alphabetic.")

    key_shifts = [LOWERCASE.index(char.lower()) for char in key]
    output = []
    key_index = 0

    for char in message:
        if char.isalpha():
            shift = -key_shifts[key_index % len(key_shifts)]
            output.append(_shift_char(char, shift))
            key_index += 1
        else:
            output.append(char)

    return "".join(output)


def xor_encrypt(message: str, key: int) -> str:
    if not 0 <= key <= 255:
        raise ValueError("XOR key must be between 0 and 255.")
    encrypted_bytes = bytes(char ^ key for char in message.encode("utf-8"))
    return encrypted_bytes.hex()


def xor_decrypt(encoded_message: str, key: int) -> str:
    if not 0 <= key <= 255:
        raise ValueError("XOR key must be between 0 and 255.")
    encrypted_bytes = bytes.fromhex(encoded_message)
    decrypted_bytes = bytes(char ^ key for char in encrypted_bytes)
    return decrypted_bytes.decode("utf-8")


def base64_encode(message: str) -> str:
    return base64.b64encode(message.encode("utf-8")).decode("utf-8")


def base64_decode(message: str) -> str:
    decoded = base64.b64decode(message.encode("utf-8"), validate=True)
    return decoded.decode("utf-8")


def process_message(algorithm: str, mode: str, message: str, key: str | None) -> str:
    algorithm = algorithm.lower()
    mode = mode.lower()

    if algorithm == "caesar":
        if mode not in {"encrypt", "decrypt"}:
            raise ValueError("Caesar supports only encrypt/decrypt.")
        if key is None:
            raise ValueError("Caesar requires a numeric key.")
        key_num = int(key)
        return caesar_encrypt(message, key_num) if mode == "encrypt" else caesar_decrypt(message, key_num)

    if algorithm == "rot13":
        return rot13_transform(message)

    if algorithm == "vigenere":
        if mode not in {"encrypt", "decrypt"}:
            raise ValueError("Vigenere supports only encrypt/decrypt.")
        if key is None:
            raise ValueError("Vigenere requires an alphabetic key.")
        return vigenere_encrypt(message, key) if mode == "encrypt" else vigenere_decrypt(message, key)

    if algorithm == "xor":
        if mode not in {"encrypt", "decrypt"}:
            raise ValueError("XOR supports only encrypt/decrypt.")
        if key is None:
            raise ValueError("XOR requires a numeric key from 0 to 255.")
        key_num = int(key)
        return xor_encrypt(message, key_num) if mode == "encrypt" else xor_decrypt(message, key_num)

    if algorithm == "base64":
        if mode == "encode":
            return base64_encode(message)
        if mode == "decode":
            return base64_decode(message)
        raise ValueError("Base64 supports only encode/decode.")

    raise ValueError(f"Unsupported algorithm: {algorithm}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt, decrypt, encode, or decode messages.")
    parser.add_argument(
        "--algorithm",
        "-a",
        required=True,
        choices=["caesar", "rot13", "vigenere", "xor", "base64"],
        help="Cryptography algorithm to use.",
    )
    parser.add_argument(
        "--mode",
        "-m",
        required=True,
        choices=["encrypt", "decrypt", "encode", "decode"],
        help="Operation mode.",
    )
    parser.add_argument("--message", "-t", required=True, help="Message to process.")
    parser.add_argument("--key", "-k", help="Algorithm key when required.")
    return parser.parse_args()


def base_encrypt(message, key):
    return caesar_encrypt(message.lower(), int(key))


def base_decrypt(encrypted_message, key):
    return caesar_decrypt(encrypted_message.lower(), int(key))


def main() -> None:
    args = parse_args()
    try:
        result = process_message(args.algorithm, args.mode, args.message, args.key)
    except (ValueError, UnicodeDecodeError, binascii.Error) as error:
        raise SystemExit(f"Error: {error}") from error

    print(result)


if __name__ == "__main__":
    main()
