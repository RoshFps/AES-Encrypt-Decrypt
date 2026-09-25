"""Command-line interface for the file encryption tool."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .crypto import CryptoError, decrypt_file, encrypt_file

EXT = ".aesf"
MIN_PASSWORD_LEN = 8


# ---------------------------------------------------------------- output ---
def _color_enabled() -> bool:
    return sys.stderr.isatty() and "NO_COLOR" not in os.environ


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _color_enabled() else text


def info(msg: str) -> None:
    print(_c("•", "36"), msg, file=sys.stderr)


def ok(msg: str) -> None:
    print(_c("✔", "32;1"), msg, file=sys.stderr)


def fail(msg: str) -> None:
    print(_c("✖", "31;1"), msg, file=sys.stderr)


class Progress:
    """Minimal progress bar on stderr; silent when stderr is not a terminal."""

    def __init__(self, total: int, label: str) -> None:
        self.total = max(total, 1)
        self.done = 0
        self.label = label
        self.enabled = sys.stderr.isatty()
        self._last = 0.0

    def __call__(self, n: int) -> None:
        self.done += n
        now = time.monotonic()
        if self.enabled and (now - self._last > 0.05 or self.done >= self.total):
            self._last = now
            frac = min(self.done / self.total, 1.0)
            bar = "█" * int(frac * 30) + "░" * (30 - int(frac * 30))
            sys.stderr.write(f"\r  {self.label} {_c(bar, '36')} {frac:6.1%}")
            sys.stderr.flush()

    def close(self) -> None:
        if self.enabled:
            sys.stderr.write("\n")


# -------------------------------------------------------------- password ---
def read_password(confirm: bool) -> str:
    env = os.environ.get("AESF_PASSWORD")
    if env:
        return env
    if not sys.stdin.isatty():
        raise CryptoError("No terminal available for the password prompt. Set AESF_PASSWORD instead.")
    pw = getpass.getpass("Password: ")
    if confirm:
        if len(pw) < MIN_PASSWORD_LEN:
            raise CryptoError(f"Use a password of at least {MIN_PASSWORD_LEN} characters.")
        if getpass.getpass("Confirm password: ") != pw:
            raise CryptoError("Passwords do not match.")
    return pw


# -------------------------------------------------------------- commands ---
def default_output(src: Path, encrypting: bool) -> Path:
    if encrypting:
        return src.with_name(src.name + EXT)
    if src.name.endswith(EXT):
        return src.with_name(src.name[: -len(EXT)])
    return src.with_name(src.name + ".decrypted")


def run(action: str, src: Path, out: Optional[Path], force: bool) -> None:
    encrypting = action == "encrypt"
    dest = out or default_output(src, encrypting)
    password = read_password(confirm=encrypting)

    size = src.stat().st_size if src.is_file() else 0
    bar = Progress(size, "Encrypting" if encrypting else "Decrypting")
    try:
        if encrypting:
            encrypt_file(src, dest, password, overwrite=force, progress=bar)
        else:
            decrypt_file(src, dest, password, overwrite=force, progress=bar)
    finally:
        bar.close()
    ok(f"{'Encrypted' if encrypting else 'Decrypted'} {src} → {dest}")


def interactive() -> None:
    print(_c("\n  AES-256-GCM File Encryption", "1"), file=sys.stderr)
    print("  1) Encrypt a file\n  2) Decrypt a file\n  3) Exit\n", file=sys.stderr)
    while True:
        choice = input("Choose [1-3]: ").strip()
        if choice == "3":
            return
        if choice not in {"1", "2"}:
            fail("Please enter 1, 2 or 3.")
            continue
        path = Path(input("File path: ").strip().strip('"'))
        try:
            run("encrypt" if choice == "1" else "decrypt", path, None, force=False)
        except CryptoError as exc:
            fail(str(exc))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aes-tool",
        description="Encrypt and decrypt files with AES-256-GCM and a scrypt-derived key.",
        epilog="Run without arguments for an interactive menu.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="action")
    for name, help_ in (("encrypt", "encrypt a file"), ("decrypt", "decrypt a file")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("file", type=Path, help="input file")
        s.add_argument("-o", "--output", type=Path, help=f"output path (default: add/remove {EXT})")
        s.add_argument("-f", "--force", action="store_true", help="overwrite the output if it exists")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.action is None:
            interactive()
        else:
            run(args.action, args.file, args.output, args.force)
    except CryptoError as exc:
        fail(str(exc))
        return 1
    except KeyboardInterrupt:
        fail("Cancelled.")
        return 130
    return 0
