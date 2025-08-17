"""Parser subpackage for yar2sig.

This subpackage contains modules responsible for converting raw YARA
rules into a structured intermediate representation.  At the moment
only a very small subset of the YARA language is supported, but the
parser has been written so that it can be replaced with a more
sophisticated implementation (e.g. using ``plyara`` or tree‑sitter)
without changing the remainder of the library.

Exports the :func:`parse_yara_rule` function.
"""

from .yara import parse_yara_rule  # noqa: F401