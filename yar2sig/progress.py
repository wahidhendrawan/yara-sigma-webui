"""Lightweight progress reporter for CLI batch operations.

Renders to stderr so it does not pollute stdout (which carries converted rules).
Auto-detects TTY: when stderr is not a terminal (e.g., piped to a file, CI), the
progress bar collapses to a single "processed N/total" line at the end.

The implementation is deliberately dependency-free (no ``tqdm``) so it stays
lightweight in the packaged wheel.
"""

from __future__ import annotations

import sys
import time
from types import TracebackType
from typing import IO, Optional


class ProgressReporter:
    """Render a compact "[###..] i/n label" bar to a stream.

    Usage::

        with ProgressReporter(total=len(files), enabled=True) as bar:
            for f in files:
                bar.update(label=f.name)
                ...  # do work
    """

    _BAR_WIDTH = 24

    def __init__(
        self,
        total: int,
        *,
        enabled: bool = True,
        stream: Optional[IO[str]] = None,
    ) -> None:
        self.total = max(0, total)
        self.stream = stream or sys.stderr
        # Only render an in-place bar when the stream is a real terminal and
        # there is more than one item to process.
        self._interactive = enabled and self.total > 1 and self._is_tty(self.stream)
        self._enabled = enabled and self.total > 0
        self._current = 0
        self._start = time.monotonic()
        self._last_render = 0.0

    @staticmethod
    def _is_tty(stream: IO[str]) -> bool:
        try:
            return bool(stream.isatty())
        except (AttributeError, ValueError):
            return False

    def update(self, *, label: str = "") -> None:
        """Advance the counter by one and re-render."""
        self._current += 1
        if not self._enabled:
            return
        if self._interactive:
            self._render(label)
        # In non-interactive mode we defer output to close() to avoid noisy logs.

    def close(self) -> None:
        if not self._enabled:
            return
        if self._interactive:
            # Final render, followed by a newline so subsequent output starts fresh.
            self._render(label="done", final=True)
            self.stream.write("\n")
        else:
            elapsed = time.monotonic() - self._start
            self.stream.write(
                f"[yar2sig] processed {self._current}/{self.total} files in {elapsed:.2f}s\n"
            )
        self.stream.flush()

    def __enter__(self) -> "ProgressReporter":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def _render(self, label: str, *, final: bool = False) -> None:
        # Throttle re-renders to ~20 fps so large batches don't churn the terminal.
        now = time.monotonic()
        if not final and (now - self._last_render) < 0.05:
            return
        self._last_render = now

        ratio = self._current / self.total if self.total else 1.0
        ratio = min(max(ratio, 0.0), 1.0)
        filled = int(self._BAR_WIDTH * ratio)
        bar = "#" * filled + "." * (self._BAR_WIDTH - filled)
        percent = int(ratio * 100)
        truncated = label[:32].ljust(32) if label else " " * 32
        self.stream.write(
            f"\r[{bar}] {self._current:>4}/{self.total:<4} {percent:>3}%  {truncated}"
        )
        self.stream.flush()
