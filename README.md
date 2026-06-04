# cryptography-basic

Simple command-line cryptography project with multiple algorithms and decode support.

## Supported options

- **Caesar cipher** (`encrypt` / `decrypt`) - requires numeric `--key`
- **ROT13** (`encrypt` / `decrypt`) - no key required (same transform both directions)
- **Vigenere cipher** (`encrypt` / `decrypt`) - requires alphabetic `--key`
- **XOR cipher** (`encrypt` / `decrypt`) - requires numeric `--key` from `0-255`
- **Base64** (`encode` / `decode`) - no key required

## Usage

```bash
python3 cryptobase.py --algorithm <name> --mode <mode> --message "text" [--key value]
```

### Examples

Caesar encrypt/decrypt:

```bash
python3 cryptobase.py -a caesar -m encrypt -t "hello world" -k 3
python3 cryptobase.py -a caesar -m decrypt -t "khoor zruog" -k 3
```

Vigenere encrypt/decrypt:

```bash
python3 cryptobase.py -a vigenere -m encrypt -t "attack at dawn" -k lemon
python3 cryptobase.py -a vigenere -m decrypt -t "lxfopv ef rnhr" -k lemon
```

XOR encrypt/decrypt:

```bash
python3 cryptobase.py -a xor -m encrypt -t "secret text" -k 42
python3 cryptobase.py -a xor -m decrypt -t "<hex output>" -k 42
```

Base64 encode/decode:

```bash
python3 cryptobase.py -a base64 -m encode -t "encode me"
python3 cryptobase.py -a base64 -m decode -t "ZW5jb2RlIG1l"
```
