"""Console entry point: ``echocorn`` and ``python -m echocorn``."""

from __future__ import annotations

import sys

from .server import main

__all__ = ["main"]


if __name__ == "__main__":
    sys.exit(main())
