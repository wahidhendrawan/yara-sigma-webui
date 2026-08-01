"""Tests for progress.py."""

from __future__ import annotations

import io

from yar2sig.progress import ProgressReporter


def test_progress_reporter_disabled():
    """When total=0 or enabled=False, no output is emitted."""
    stream = io.StringIO()
    with ProgressReporter(total=0, enabled=True, stream=stream):
        pass
    assert stream.getvalue() == ""

    stream = io.StringIO()
    with ProgressReporter(total=10, enabled=False, stream=stream):
        pass
    assert stream.getvalue() == ""


def test_progress_reporter_non_interactive():
    """When stream is not a TTY, we emit a single summary line at close()."""
    stream = io.StringIO()
    with ProgressReporter(total=3, enabled=True, stream=stream) as bar:
        bar.update(label="file1.yar")
        bar.update(label="file2.yar")
        bar.update(label="file3.yar")
    
    output = stream.getvalue()
    assert "processed 3/3" in output
    assert "files in" in output
    # Should not contain the interactive bar characters
    assert "[#" not in output


def test_progress_reporter_single_item():
    """When total=1, non-interactive mode is forced (no bar needed)."""
    stream = io.StringIO()
    with ProgressReporter(total=1, enabled=True, stream=stream) as bar:
        bar.update(label="single.yar")
    
    output = stream.getvalue()
    assert "processed 1/1" in output


def test_progress_reporter_update_increments():
    """Each update() call increments the counter."""
    stream = io.StringIO()
    reporter = ProgressReporter(total=5, enabled=True, stream=stream)
    assert reporter._current == 0
    reporter.update()
    assert reporter._current == 1
    reporter.update()
    assert reporter._current == 2
    reporter.close()
