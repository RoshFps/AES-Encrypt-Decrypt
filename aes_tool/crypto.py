"""Authenticated file encryption with AES-256-GCM.

File format (all integers big-endian)::

    +--------+---------+--------------+-----------+------------+------------+----------+
    | magic  | version | scrypt log2N | salt      | nonce      | ciphertext | tag      |
    | 4 B    | 1 B     | 1 B          | 16 B      | 12 B       | n B        | 16 B     |
    +--------+---------+--------------+-----------+------------+------------+----------+

The 34-byte header is bound to the ciphertext as associated data, so any
change to it (for example lowering the KDF cost) makes decryption fail.

Decryption writes to a temporary file next to the destination and only
renames it into place after the GCM tag verifies, so unauthenticated
plaintext is never left on disk.
"""

from __future__ import annotations

import os
import secrets
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AESF"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
DEFAULT_LOG2_N = 15  # scrypt N = 32768, r = 8, p = 1  (~32 MiB memory)
MIN_LOG2_N = 14
MAX_LOG2_N = 22
CHUNK_SIZE = 64 * 1024

_HEADER = struct.Struct(f">4sBB{SALT_LEN}s{NONCE_LEN}s")
HEADER_LEN = _HEADER.size

ProgressCallback = Optional[Callable[[int], None]]


class CryptoError(Exception):
    """Base error for anything the user should see as a clean message."""


class InvalidFileError(CryptoError):
    """The input is not a file produced by this tool, or it is truncated."""


class AuthenticationError(CryptoError):
    """Wrong password, or the file was modified after encryption."""


@dataclass(frozen=True)
class Header:
    log2_n: int
    salt: bytes
    nonce: bytes

    def pack(self) -> bytes:
        return _HEADER.pack(MAGIC, VERSION, self.log2_n, self.salt, self.nonce)

    @classmethod
    def unpack(cls, raw: bytes) -> "Header":
        if len(raw) != HEADER_LEN:
            raise InvalidFileError("File is too short to be an encrypted file.")
        magic, version, log2_n, salt, nonce = _HEADER.unpack(raw)
        if magic != MAGIC:
            raise InvalidFileError("Not an encrypted file (bad magic bytes).")
        if version != VERSION:
            raise InvalidFileError(f"Unsupported file version {version}.")
        if not MIN_LOG2_N <= log2_n <= MAX_LOG2_N:
            raise InvalidFileError("Key-derivation parameters are out of range.")
        return cls(log2_n=log2_n, salt=salt, nonce=nonce)


def derive_key(password: str, salt: bytes, log2_n: int = DEFAULT_LOG2_N) -> bytes:
    """Stretch a password into a 256-bit key with scrypt."""
    if not password:
        raise CryptoError("Password must not be empty.")
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2**log2_n, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    password: str,
    *,
    log2_n: int = DEFAULT_LOG2_N,
    progress: ProgressCallback = None,
) -> None:
    header = Header(log2_n=log2_n, salt=secrets.token_bytes(SALT_LEN), nonce=secrets.token_bytes(NONCE_LEN))
    raw_header = header.pack()
    key = derive_key(password, header.salt, log2_n)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(header.nonce)).encryptor()
    encryptor.authenticate_additional_data(raw_header)

    dst.write(raw_header)
    while chunk := src.read(CHUNK_SIZE):
        dst.write(encryptor.update(chunk))
        if progress:
            progress(len(chunk))
    dst.write(encryptor.finalize())
    dst.write(encryptor.tag)


def decrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    password: str,
    *,
    total_size: int,
    progress: ProgressCallback = None,
) -> None:
    """Decrypt ``src`` into ``dst``. ``dst`` must be discarded if this raises."""
    if total_size < HEADER_LEN + TAG_LEN:
        raise InvalidFileError("File is too short to be an encrypted file.")

    raw_header = src.read(HEADER_LEN)
    header = Header.unpack(raw_header)

    body_len = total_size - HEADER_LEN - TAG_LEN
    src.seek(HEADER_LEN + body_len)
    tag = src.read(TAG_LEN)
    src.seek(HEADER_LEN)

    key = derive_key(password, header.salt, header.log2_n)
    decryptor = Cipher(algorithms.AES(key), modes.GCM(header.nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(raw_header)

    remaining = body_len
    while remaining:
        chunk = src.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise InvalidFileError("File ended unexpectedly.")
        remaining -= len(chunk)
        dst.write(decryptor.update(chunk))
        if progress:
            progress(len(chunk))
    try:
        dst.write(decryptor.finalize())
    except InvalidTag:
        raise AuthenticationError(
            "Decryption failed: wrong password, or the file has been modified."
        ) from None


def _atomic_output(dest: Path, overwrite: bool):
    if dest.exists() and not overwrite:
        raise CryptoError(f"{dest} already exists. Use --force to overwrite it.")
    fd, tmp = tempfile.mkstemp(prefix=".aesf-", dir=dest.parent or Path("."))
    return os.fdopen(fd, "wb"), Path(tmp)


def _run_to_file(func, src_path: Path, dest: Path, overwrite: bool, **kwargs) -> None:
    src_path = Path(src_path)
    dest = Path(dest)
    if not src_path.is_file():
        raise CryptoError(f"{src_path} does not exist or is not a regular file.")
    if src_path.resolve() == dest.resolve():
        raise CryptoError("Input and output must be different files.")

    out, tmp = _atomic_output(dest, overwrite)
    try:
        with open(src_path, "rb") as src, out:
            func(src, out, **kwargs)
        os.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def encrypt_file(src: Path, dest: Path, password: str, *, overwrite: bool = False,
                 log2_n: int = DEFAULT_LOG2_N, progress: ProgressCallback = None) -> None:
    _run_to_file(encrypt_stream, src, dest, overwrite, password=password, log2_n=log2_n, progress=progress)


def decrypt_file(src: Path, dest: Path, password: str, *, overwrite: bool = False,
                 progress: ProgressCallback = None) -> None:
    size = Path(src).stat().st_size if Path(src).is_file() else 0
    _run_to_file(decrypt_stream, src, dest, overwrite, password=password, total_size=size, progress=progress)
