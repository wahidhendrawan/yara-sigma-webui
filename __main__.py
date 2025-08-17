"""Executable module for yar2sig.

When you run ``python -m yar2sig`` this module is executed and
delegates to the CLI implementation in :mod:`yar2sig.cli`.
"""

from .cli import main

if __name__ == '__main__':
    main()