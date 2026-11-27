// Copyright 2026 agent-bridge contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Synchronous newline-delimited JSON-RPC transport over `stdio` for MCP.
//!
//! Enforces strict UTF-8, CRLF tolerance, bounded memory allocation (1 MiB
//! default limit on both input and output frames), silence on notifications,
//! and orderly EOF termination using only `std`.

use std::io::{self, BufRead, Write};

/// Default maximum payload size per line-delimited frame (1 MiB).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Serves an MCP stdio stream using the default [`MAX_FRAME_BYTES`] (1 MiB)
/// limit for both input and output frames.
pub fn serve(
    reader: impl BufRead,
    writer: impl Write,
    dispatch: impl FnMut(&str) -> Option<String>,
) -> io::Result<()> {
    serve_with_limits(reader, writer, MAX_FRAME_BYTES, MAX_FRAME_BYTES, dispatch)
}

/// Serves an MCP stdio stream with explicit per-frame byte limits for input
/// and output payloads (excluding line terminators).
pub fn serve_with_limits(
    reader: impl BufRead,
    writer: impl Write,
    max_input_bytes: usize,
    max_output_bytes: usize,
    mut dispatch: impl FnMut(&str) -> Option<String>,
) -> io::Result<()> {
    serve_observed_with_limits(reader, writer, max_input_bytes, max_output_bytes,
        |line| (dispatch(line), ()), |(), _| {})
}

/// Completion of one bounded input frame, not an acknowledgement by the client.
/// Written means the complete response and its newline were flushed successfully.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameCompletion {
    Written,
    Silent,
    OutputTooLarge,
    OutputFailed,
}

/// Same framing and limits as serve; retain a caller-owned receipt until the
/// response has actually been flushed. No callback for rejected input frames.
pub fn serve_observed<T>(
    reader: impl BufRead,
    writer: impl Write,
    dispatch: impl FnMut(&str) -> (Option<String>, T),
    complete: impl FnMut(T, FrameCompletion),
) -> io::Result<()> {
    serve_observed_with_limits(reader, writer, MAX_FRAME_BYTES, MAX_FRAME_BYTES, dispatch, complete)
}

fn serve_observed_with_limits<T>(
    mut reader: impl BufRead,
    mut writer: impl Write,
    max_input_bytes: usize,
    max_output_bytes: usize,
    mut dispatch: impl FnMut(&str) -> (Option<String>, T),
    mut complete: impl FnMut(T, FrameCompletion),
) -> io::Result<()> {
    let mut line_buf = Vec::new();

    loop {
        match read_bounded_line(&mut reader, &mut line_buf, max_input_bytes)? {
            ReadLineOutcome::Eof => return Ok(()),
            ReadLineOutcome::Line => {}
        }

        let line = std::str::from_utf8(&line_buf).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid UTF-8 in stdio input frame",
            )
        })?;

        if line.trim().is_empty() {
            continue;
        }

        let (response, receipt) = dispatch(line);
        if let Some(response) = response {
            let result = write_bounded_line(&mut writer, &response, max_output_bytes);
            let completion = if result.is_ok() { FrameCompletion::Written }
                else if response.len() > max_output_bytes { FrameCompletion::OutputTooLarge }
                else { FrameCompletion::OutputFailed };
            complete(receipt, completion);
            result?;
        } else {
            complete(receipt, FrameCompletion::Silent);
        }
    }
}

enum ReadLineOutcome {
    Eof,
    Line,
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> io::Result<ReadLineOutcome> {
    buf.clear();
    let mut pending_cr = false;

    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };

        if available.is_empty() {
            if !pending_cr && buf.is_empty() {
                return Ok(ReadLineOutcome::Eof);
            }
            if pending_cr {
                push_bounded(buf, b"\r", max_bytes)?;
            }
            return Ok(ReadLineOutcome::Line);
        }

        if pending_cr {
            if available[0] == b'\n' {
                reader.consume(1);
                return Ok(ReadLineOutcome::Line);
            }
            push_bounded(buf, b"\r", max_bytes)?;
        }

        if let Some(nl_pos) = available.iter().position(|&b| b == b'\n') {
            let line_part = &available[..nl_pos];
            let payload_part = line_part.strip_suffix(b"\r").unwrap_or(line_part);

            push_bounded(buf, payload_part, max_bytes)?;
            reader.consume(nl_pos + 1);
            return Ok(ReadLineOutcome::Line);
        }

        let (chunk_without_trailing_cr, ends_with_cr) = match available.strip_suffix(b"\r") {
            Some(stripped) => (stripped, true),
            None => (available, false),
        };

        push_bounded(buf, chunk_without_trailing_cr, max_bytes)?;
        pending_cr = ends_with_cr;

        let consumed = available.len();
        reader.consume(consumed);
    }
}

fn push_bounded(buf: &mut Vec<u8>, bytes: &[u8], max_bytes: usize) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }

    let required = buf
        .len()
        .checked_add(bytes.len())
        .filter(|&len| len <= max_bytes)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stdio input frame exceeds maximum size",
            )
        })?;

    if required > buf.capacity() {
        let target_capacity = buf
            .capacity()
            .saturating_mul(2)
            .max(256)
            .max(required)
            .min(max_bytes);
        buf.try_reserve_exact(target_capacity - buf.len())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "failed to allocate stdio input frame buffer",
                )
            })?;
    }

    buf.extend_from_slice(bytes);
    Ok(())
}

fn write_bounded_line<W: Write>(
    writer: &mut W,
    response: &str,
    max_bytes: usize,
) -> io::Result<()> {
    if response.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stdio output frame exceeds maximum size",
        ));
    }

    if response.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stdio output frame must not be empty",
        ));
    }

    if response.as_bytes().iter().any(|&b| b == b'\n' || b == b'\r') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stdio output frame contains embedded line break",
        ));
    }

    writer.write_all(response.as_bytes())?;
    writer.write_all(b"\n")?;
    flush_all(writer)
}

fn flush_all<W: Write>(writer: &mut W) -> io::Result<()> {
    loop {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}
