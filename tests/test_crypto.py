import io
import os
import tempfile
import unittest
from pathlib import Path

from aes_tool.crypto import (
    HEADER_LEN,
    MIN_LOG2_N,
    AuthenticationError,
    CryptoError,
    InvalidFileError,
    decrypt_file,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
)

FAST = MIN_LOG2_N  # keep scrypt cheap in tests


def enc(data: bytes, pw: str = "correct horse") -> bytes:
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, pw, log2_n=FAST)
    return out.getvalue()


def dec(blob: bytes, pw: str = "correct horse") -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, pw, total_size=len(blob))
    return out.getvalue()


class StreamTests(unittest.TestCase):
    def test_round_trip(self):
        for size in (0, 1, 1000, 64 * 1024, 200_003):
            data = os.urandom(size)
            self.assertEqual(dec(enc(data)), data)

    def test_ciphertext_is_randomised(self):
        self.assertNotEqual(enc(b"same"), enc(b"same"))

    def test_wrong_password(self):
        with self.assertRaises(AuthenticationError):
            dec(enc(b"secret"), "wrong password")

    def test_tampered_body(self):
        blob = bytearray(enc(b"attack at dawn"))
        blob[HEADER_LEN] ^= 1
        with self.assertRaises(AuthenticationError):
            dec(bytes(blob))

    def test_tampered_header(self):
        blob = bytearray(enc(b"attack at dawn"))
        blob[10] ^= 1  # inside the salt
        with self.assertRaises(AuthenticationError):
            dec(bytes(blob))

    def test_not_our_format(self):
        with self.assertRaises(InvalidFileError):
            dec(b"X" * 100)

    def test_truncated(self):
        with self.assertRaises(InvalidFileError):
            dec(enc(b"hi")[:20])

    def test_empty_password_rejected(self):
        with self.assertRaises(CryptoError):
            enc(b"x", "")


class FileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.plain = self.root / "notes.txt"
        self.plain.write_bytes(b"hello world\n" * 1000)

    def tearDown(self):
        self.dir.cleanup()

    def test_file_round_trip(self):
        enc_path, out = self.root / "notes.txt.aesf", self.root / "out.txt"
        encrypt_file(self.plain, enc_path, "pw123456", log2_n=FAST)
        decrypt_file(enc_path, out, "pw123456")
        self.assertEqual(out.read_bytes(), self.plain.read_bytes())

    def test_refuses_overwrite(self):
        target = self.root / "exists"
        target.write_bytes(b"keep me")
        with self.assertRaises(CryptoError):
            encrypt_file(self.plain, target, "pw123456", log2_n=FAST)
        self.assertEqual(target.read_bytes(), b"keep me")

    def test_failed_decrypt_leaves_no_output(self):
        enc_path, out = self.root / "e", self.root / "d"
        encrypt_file(self.plain, enc_path, "pw123456", log2_n=FAST)
        with self.assertRaises(AuthenticationError):
            decrypt_file(enc_path, out, "nope")
        self.assertFalse(out.exists())
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith(".aesf-")], [])

    def test_missing_input(self):
        with self.assertRaises(CryptoError):
            encrypt_file(self.root / "missing", self.root / "x", "pw123456")


if __name__ == "__main__":
    unittest.main()
