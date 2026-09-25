# AES-Encrypt-Decrypt

[![CI](https://github.com/RoshFps/AES-Encrypt-Decrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/RoshFps/AES-Encrypt-Decrypt/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A small command-line tool that encrypts and decrypts any file (documents, images, video, archives) with a password.

It uses **AES-256-GCM**, an authenticated cipher, with a key derived from your password by **scrypt**. Wrong passwords and tampered files are detected and rejected instead of producing garbage output.

## Quick start

```bash
git clone https://github.com/RoshFps/AES-Encrypt-Decrypt.git
cd AES-Encrypt-Decrypt
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m aes_tool encrypt report.pdf          # writes report.pdf.aesf
python -m aes_tool decrypt report.pdf.aesf     # writes report.pdf
python -m aes_tool                             # interactive menu
```

| Option | Meaning |
| --- | --- |
| `-o, --output PATH` | Choose where to write the result |
| `-f, --force` | Overwrite the output if it already exists |
| `--version` | Print the version |

Passwords are read with a hidden prompt and must be at least 8 characters when encrypting. For scripts, set `AESF_PASSWORD` in the environment instead. Keep in mind that environment variables can be visible to other processes run by the same user.

## How it works

```
password ──scrypt(N=2^15, r=8, p=1, 16-byte random salt)──► 256-bit key
key + 96-bit random nonce ──AES-GCM──► ciphertext + 128-bit tag
```

Encrypted file layout:

| Field | Size | Notes |
| --- | --- | --- |
| Magic `AESF` | 4 B | Identifies the format |
| Version | 1 B | Currently `1` |
| scrypt log2(N) | 1 B | Stored so the cost can be raised later |
| Salt | 16 B | Random per file |
| Nonce | 12 B | Random per file |
| Ciphertext | n B | Same length as the input |
| GCM tag | 16 B | Authenticates header and ciphertext |

Design choices:

- **Authenticated encryption.** The whole header is passed to GCM as associated data, so editing any byte of the file, including the KDF cost, fails verification.
- **No partial plaintext on failure.** Decryption writes to a temporary file and only renames it into place once the tag verifies.
- **Streaming.** Files are processed in 64 KiB chunks, so large files don't need to fit in memory.
- **Safe defaults.** The tool refuses to overwrite existing files or write over its own input unless you ask it to.

## Threat model

The tool protects confidentiality and integrity of files at rest against someone who gets a copy of the encrypted file but not the password.

It does **not** protect against malware on your machine, weak or reused passwords, or the original plaintext still being on disk. Delete the original securely if that matters to you.

## Development

```bash
python -m unittest discover -s tests -t . -v
```

CI runs the tests on Python 3.9, 3.11 and 3.12, plus `bandit` static analysis and `pip-audit` dependency checks.

## Changelog

**2.0.0**: Replaced the original single-byte XOR scheme, which could be reversed without the key, with AES-256-GCM and scrypt. Added the CLI, tests and CI. Files encrypted by 1.x cannot be opened by 2.0.

## Credits

The original 1.x script is based on a file-encryption tool by Sri Manikanta Palakollu.

## License

MIT, see [LICENSE](LICENSE).
