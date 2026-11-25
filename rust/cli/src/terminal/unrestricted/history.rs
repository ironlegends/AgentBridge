//! Ordered, bounded output for the unified line-oriented reader.
use std::collections::VecDeque;

use super::{MAX_REPLY_BYTES, MAX_STREAM_BYTES};
use serde_json::{json, Value};

#[derive(Default)]
pub(super) struct History {
    // One source tag per byte keeps memory bounded even if the pipes alternate
    // on every byte. UTF-8 scalars are appended and evicted as whole units.
    bytes: VecDeque<(u8, bool)>,
    pending: [Vec<u8>; 2],
    skip_lf: [bool; 2],
    discarded: [u64; 2],
    evicted_lines: u64,
    partial_first_line: bool,
    cursor: u64,
}

impl History {
    fn base(&self) -> u64 { self.discarded.iter().sum() }

    pub(super) fn end(&self) -> u64 { self.base() + self.bytes.len() as u64 }

    pub(super) fn unread(&self) -> bool { self.end() > self.cursor }

    pub(super) fn since(&self, mark: u64) -> (String, String, bool) {
        let start = mark.saturating_sub(self.base()).min(self.bytes.len() as u64) as usize;
        let (end, _, _, stdout, stderr) = self.page(start, 1000);
        (stdout, stderr, mark < self.base() || end < self.bytes.len())
    }

    pub(super) fn push(&mut self, stdout: bool, bytes: &[u8], eof: bool) {
        let source = usize::from(!stdout);
        if bytes.is_empty() && self.pending[source].is_empty() { return; }
        let mut joined = std::mem::take(&mut self.pending[source]);
        joined.extend_from_slice(bytes);
        let mut rest = joined.as_slice();
        while !rest.is_empty() {
            match std::str::from_utf8(rest) {
                Ok(text) => { self.append(stdout, text); break; }
                Err(error) => {
                    let (valid, invalid) = rest.split_at(error.valid_up_to());
                    self.append(stdout, std::str::from_utf8(valid).expect("validated prefix"));
                    match error.error_len() {
                        Some(n) => { self.append(stdout, "\u{fffd}"); rest = &invalid[n..]; }
                        None => {
                            if eof { self.append(stdout, "\u{fffd}"); }
                            else { self.pending[source].extend_from_slice(invalid); }
                            break;
                        }
                    }
                }
            }
        }
    }

    fn append(&mut self, stdout: bool, text: &str) {
        let source = usize::from(!stdout);
        for byte in text.bytes() {
            let skip = self.skip_lf[source] && byte == b'\n';
            self.skip_lf[source] = byte == b'\r';
            if !skip { self.bytes.push_back((if byte == b'\r' { b'\n' } else { byte }, stdout)); }
        }
        while self.bytes.len() > MAX_STREAM_BYTES ||
              self.bytes.front().is_some_and(|(byte, _)| byte & 0xc0 == 0x80) {
            let (byte, source_stdout) = self.bytes.pop_front().expect("over budget");
            self.discarded[usize::from(!source_stdout)] += 1;
            self.evicted_lines += u64::from(byte == b'\n');
            self.partial_first_line = byte != b'\n';
        }
    }

    pub(super) fn read(&mut self, offset: i64, length: usize) -> Value {
        let total = self.bytes.iter().filter(|(byte, _)| *byte == b'\n').count()
            + usize::from(self.bytes.back().is_some_and(|(byte, _)| *byte != b'\n'));
        let base = self.base();
        let start = if offset == 0 {
            self.cursor.saturating_sub(base).min(self.bytes.len() as u64) as usize
        } else {
            let line = if offset < 0 { total.saturating_sub(offset.unsigned_abs() as usize) }
                else { (offset as usize).min(total) };
            if line == 0 { 0 } else {
                self.bytes.iter().enumerate().filter(|(_, (byte, _))| *byte == b'\n')
                    .nth(line - 1).map_or(self.bytes.len(), |(i, _)| i + 1)
            }
        };
        let start_line = if start == self.bytes.len() { total } else {
            self.bytes.iter().take(start).filter(|(byte, _)| *byte == b'\n').count()
        };
        let (end, count, combined, stdout, stderr) = self.page(start, length);
        if offset == 0 { self.cursor = base + end as u64; }
        json!({
            "offset":start_line, "length":count, "total_lines":total,
            "content":combined, "stdout":stdout, "stderr":stderr,
            "has_more":end < self.bytes.len(), "evicted_lines":self.evicted_lines,
            "first_line_truncated":self.partial_first_line,
            "stdout_truncated":self.discarded[0] != 0, "stderr_truncated":self.discarded[1] != 0,
            "stdout_dropped_bytes":self.discarded[0], "stderr_dropped_bytes":self.discarded[1],
        })
    }

    fn page(&self, start: usize, length: usize) -> (usize, usize, String, String, String) {
        let mut end = start;
        let mut newlines = 0;
        for (byte, _) in self.bytes.iter().skip(start).take(MAX_REPLY_BYTES) {
            end += 1;
            if *byte == b'\n' {
                newlines += 1;
                if newlines == length { break; }
            }
        }
        while end > start && self.bytes.get(end).is_some_and(|(byte, _)| byte & 0xc0 == 0x80) {
            end -= 1;
        }
        let mut combined = Vec::with_capacity(end - start);
        let mut streams = [Vec::new(), Vec::new()];
        for &(byte, stdout) in self.bytes.range(start..end) {
            combined.push(byte);
            streams[usize::from(!stdout)].push(byte);
        }
        let count = newlines + usize::from(combined.last().is_some_and(|byte| *byte != b'\n'));
        let [stdout, stderr] = streams;
        (end, count,
            String::from_utf8(combined).expect("complete UTF-8"),
            String::from_utf8(stdout).expect("complete stdout UTF-8"),
            String::from_utf8(stderr).expect("complete stderr UTF-8"))

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_follow_partial_lines_without_duplicate_or_lost_text() {
        let mut history = History::default();
        history.push(true, b"prefix \xf0\x9f", false);
        assert_eq!(history.read(0, 1)["content"], "prefix ");
        history.push(false, b"diagnostic\r", false);
        history.push(true, b"\x98\x80\r\n", false);
        history.push(false, b"\n", false);
        let page = history.read(0, 3);
        assert_eq!(page["stdout"], "😀\n");
        assert_eq!(page["stderr"], "diagnostic\n");
        assert!(!history.unread());
        assert_eq!(history.read(-1, 1)["content"], "😀\n");
        history.push(false, b"\xe2", true);
        assert_eq!(history.read(0, 1)["stderr"], "�");
        let past_end = history.read(1000, 2);
        assert_eq!(past_end["offset"], past_end["total_lines"]);
        assert_eq!(past_end["length"], 0);
    }

    #[test]
    fn eviction_keeps_latest_data_and_long_lines_progress_by_complete_scalars() {
        let mut history = History::default();
        history.push(false, b"evict me\n", false);
        let text = "€".repeat(MAX_STREAM_BYTES / 3 + 17);
        history.push(true, text.as_bytes(), false);
        let mut read = String::new();
        while history.unread() {
            let page = history.read(0, 1);
            assert!(page["first_line_truncated"].as_bool().unwrap());
            assert_eq!(page["evicted_lines"], 1);
            assert_eq!(page["stderr"], "");
            let chunk = page["stdout"].as_str().unwrap();
            assert!(!chunk.is_empty() && chunk.len() <= MAX_REPLY_BYTES);
            read.push_str(chunk);
        }
        assert_eq!(read, "€".repeat(MAX_STREAM_BYTES / 3));
    }
}