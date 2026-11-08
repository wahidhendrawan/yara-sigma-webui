//! Compact `[###..] i/n label` progress bar for batch CLI runs, rendered to stderr so stdout
//! keeps carrying converted rules. Interactive only on a terminal with more than one item;
//! otherwise a single `processed N/total` summary line at the end.

use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

const BAR_WIDTH: usize = 24;

pub struct ProgressReporter<W: Write = io::Stderr> {
    total: usize,
    stream: W,
    interactive: bool,
    enabled: bool,
    current: usize,
    start: Instant,
    last_render: Option<Instant>,
    closed: bool,
}

impl ProgressReporter<io::Stderr> {
    pub fn stderr(total: usize, enabled: bool) -> Self {
        let interactive = io::stderr().is_terminal();
        Self::new(total, enabled, io::stderr(), interactive)
    }
}

impl<W: Write> ProgressReporter<W> {
    pub fn new(total: usize, enabled: bool, stream: W, is_tty: bool) -> Self {
        Self {
            total,
            stream,
            interactive: enabled && total > 1 && is_tty,
            enabled: enabled && total > 0,
            current: 0,
            start: Instant::now(),
            last_render: None,
            closed: false,
        }
    }

    pub fn current(&self) -> usize {
        self.current
    }

    /// Advance the counter by one and re-render.
    pub fn update(&mut self, label: &str) {
        self.current += 1;
        if self.enabled && self.interactive {
            self.render(label, false);
        }
        // In non-interactive mode output is deferred to close() to avoid noisy logs.
    }

    pub fn close(&mut self) {
        if !self.enabled || self.closed {
            return;
        }
        self.closed = true;
        if self.interactive {
            self.render("done", true);
            let _ = self.stream.write_all(b"\n");
        } else {
            let elapsed = self.start.elapsed().as_secs_f64();
            let _ = writeln!(
                self.stream,
                "[yar2sig] processed {}/{} files in {elapsed:.2}s",
                self.current, self.total
            );
        }
        let _ = self.stream.flush();
    }

    fn render(&mut self, label: &str, final_render: bool) {
        // Throttle re-renders to ~20 fps so large batches don't churn the terminal.
        let now = Instant::now();
        if !final_render
            && self
                .last_render
                .is_some_and(|last| now - last < Duration::from_millis(50))
        {
            return;
        }
        self.last_render = Some(now);
        let ratio = if self.total > 0 {
            (self.current as f64 / self.total as f64).clamp(0.0, 1.0)
        } else {
            1.0
        };
        let filled = (BAR_WIDTH as f64 * ratio) as usize;
        let bar = format!("{}{}", "#".repeat(filled), ".".repeat(BAR_WIDTH - filled));
        let truncated: String = label.chars().take(32).collect();
        let _ = write!(
            self.stream,
            "\r[{bar}] {:>4}/{:<4} {:>3}%  {truncated:<32}",
            self.current,
            self.total,
            (ratio * 100.0) as usize
        );
        let _ = self.stream.flush();
    }
}

impl<W: Write> Drop for ProgressReporter<W> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_emits_nothing() {
        let mut out = Vec::new();
        ProgressReporter::new(0, true, &mut out, false).update("x");
        assert!(out.is_empty());
        let mut out = Vec::new();
        ProgressReporter::new(10, false, &mut out, true).update("x");
        assert!(out.is_empty());
    }

    #[test]
    fn non_interactive_summary_line() {
        let mut out = Vec::new();
        {
            let mut bar = ProgressReporter::new(3, true, &mut out, false);
            for name in ["file1.yar", "file2.yar", "file3.yar"] {
                bar.update(name);
            }
            assert_eq!(bar.current(), 3);
            bar.close();
            bar.close(); // idempotent, Drop calls it again
        }
        let output = String::from_utf8(out).unwrap();
        assert!(
            output.contains("processed 3/3")
                && output.contains("files in")
                && !output.contains("[#")
        );
        assert_eq!(output.matches("processed").count(), 1);

        let mut out = Vec::new();
        ProgressReporter::new(1, true, &mut out, true).update("single.yar");
        assert!(String::from_utf8(out).unwrap().contains("processed 1/1"));
    }

    #[test]
    fn interactive_bar() {
        let mut out = Vec::new();
        {
            let mut bar = ProgressReporter::new(2, true, &mut out, true);
            bar.update("a.yar");
        }
        let output = String::from_utf8(out).unwrap();
        assert!(output.starts_with("\r[############............]    1/2     50%  a.yar"));
        assert!(output.ends_with(&format!("50%  {:<32}\n", "done")));
    }
}
