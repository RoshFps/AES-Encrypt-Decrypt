"""Backwards-compatible entry point. Prefer: python -m aes_tool"""

import sys

from aes_tool.cli import main

if __name__ == "__main__":
    sys.exit(main())
