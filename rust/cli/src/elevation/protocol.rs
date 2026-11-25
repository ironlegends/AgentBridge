use serde::{Deserialize, Serialize};
use std::io;

pub(super) const MAX_REQUEST: usize = 512 * 1024;
pub(super) const MAX_RECEIPT: usize = 4096;
pub(super) const MAX_MAPPING: usize = 8 * 1024 * 1024;

pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn valid_nonce(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

// Elevation never resolves relative names, UNC/device paths, DOS aliases or
// alternate streams. Native preparation additionally pins physical identity.
fn ordinary_local_path(units: &[u16]) -> bool {
    if units.len() < 3 || units.len() > 32_766 { return false; }
    let Ok(text) = String::from_utf16(units) else { return false; };
    let bytes = text.as_bytes();
    if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' { return false; }
    if text.len() == 3 { return true; }
    text[3..].split('\\').all(|part| {
        if part.is_empty() || part == "." || part == ".." || part.ends_with('.') || part.ends_with(' ')
            || part.chars().any(|ch| ch.is_control() || "<>:\\\"|?*/".contains(ch)) { return false; }
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") { return false; }
        !["COM", "LPT"].into_iter().any(|prefix| stem.strip_prefix(prefix).is_some_and(|suffix|
            suffix.chars().count() == 1 && suffix.chars().next().is_some_and(|ch|
                matches!(ch, '1'..='9' | '¹' | '²' | '³'))))
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub version: u32,
    pub nonce: String,
    pub executable: Vec<u16>,
    pub command: Vec<u16>,
    pub cwd: Vec<u16>,
    pub visible: bool,
}

impl Request {
    pub(super) fn validate(&self, nonce: &str) -> io::Result<()> {
        let path = ordinary_local_path;
        if self.version != 1 || !valid_nonce(nonce) || self.nonce != nonce
            || !path(&self.executable) || !path(&self.cwd)
            || self.command.len() < 2 || self.command.len() > 32_767
            || self.command.last() != Some(&0)
            || self.command[..self.command.len() - 1].contains(&0)
            || String::from_utf16(&self.command[..self.command.len() - 1]).is_err()
        {
            return Err(invalid("Invalid or uncorrelated elevation request"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    pub request: Request,
    pub environment: Vec<u16>,
}

impl Payload {
    pub(super) fn validate(&self, nonce: &str) -> io::Result<()> {
        self.request.validate(nonce)?;
        let block = &self.environment;
        if block.len() < 2 || block.len() > 32_767 || !block.ends_with(&[0, 0]) {
            return Err(invalid("Invalid elevation environment block"));
        }
        if block == &[0, 0] { return Ok(()); }
        let mut names = std::collections::BTreeSet::new();
        for entry in block[..block.len()-2].split(|unit| *unit == 0) {
            let text = String::from_utf16(entry).map_err(|_| invalid("Invalid elevation environment encoding"))?;
            let (name, value) = text.split_once('=').ok_or_else(|| invalid("Invalid elevation environment entry"))?;
            let upper = name.to_ascii_uppercase();
            if !matches!(upper.as_str(), "SYSTEMROOT" | "WINDIR" | "TEMP" | "TMP")
                || !names.insert(upper)
                || !ordinary_local_path(&value.encode_utf16().collect::<Vec<_>>()) {
                return Err(invalid("Unapproved or ambiguous elevation environment entry"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Receipt {
    ConsentPending { version: u32, nonce: String },
    Started { version: u32, nonce: String, command_pid: u32, elevated: bool },
    Failed { version: u32, nonce: String, stage: String, win32_error: Option<u32> },
    Completed { version: u32, nonce: String, command_pid: u32, exit_code: Option<i32>, error: Option<String>, win32_error: Option<u32> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub(crate) enum Progress {
    Preparing,
    AwaitingConsent,
    Started { command_pid: u32 },
    Failed { stage: String, win32_error: Option<u32> },
    Completed { command_pid: u32, exit_code: Option<i32>, error: Option<String>, win32_error: Option<u32> },
}

pub(super) fn frame<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > limit || bytes.len() > u32::MAX as usize {
        return Err(invalid("Elevation frame exceeds its byte budget"));
    }
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(&bytes);
    Ok(framed)
}

pub(super) fn receipt_frame(value: &Receipt) -> io::Result<Vec<u8>> {
    let mut encoded = vec![0];
    encoded.extend(frame(value, MAX_RECEIPT)?);
    Ok(encoded)
}

pub(super) fn output_frame(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > 65_536 { return Err(invalid("Invalid elevation output frame size")); }
    let mut encoded = vec![1];
    encoded.extend((bytes.len() as u32).to_be_bytes());
    encoded.extend(bytes);
    Ok(encoded)
}

pub(super) struct Decoder {
    nonce: String,
    buffer: Vec<u8>,
    poisoned: bool,
    pub(super) progress: Progress,
}

impl Decoder {
    pub(super) fn new(nonce: String) -> io::Result<Self> {
        if !valid_nonce(&nonce) { return Err(invalid("Invalid elevation nonce")); }
        Ok(Self { nonce, buffer: Vec::new(), poisoned: false, progress: Progress::Preparing })
    }

    fn terminal(&self) -> bool {
        matches!(self.progress, Progress::Failed { .. } | Progress::Completed { .. })
    }

    pub(super) fn feed(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        if self.poisoned { return Err(invalid("Elevation stream is invalid")); }
        let previous = self.progress.clone();
        let result = self.feed_frames(input);
        if result.is_err() {
            // Do not publish a terminal success from an invalid batch, and
            // never resume parsing a stream after a protocol violation.
            self.progress = previous;
            self.poisoned = true;
            self.buffer.clear();
        }
        result
    }

    fn feed_frames(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        const HEADER: usize = 5;
        const MAX_OUTPUT: usize = 65_536;
        if input.len() > MAX_OUTPUT
            || self.buffer.len().saturating_add(input.len()) > HEADER + 2 * MAX_OUTPUT {
            return Err(invalid("Elevation frame buffer exceeds its byte budget"));
        }
        self.buffer.extend_from_slice(input);
        let mut consumed = 0;
        let mut output = Vec::new();
        while consumed < self.buffer.len() {
            if self.terminal() {
                return Err(invalid("Unexpected data after terminal elevation receipt"));
            }
            let frame = &self.buffer[consumed..];
            let limit = match frame[0] {
                0 => MAX_RECEIPT,
                1 if matches!(self.progress, Progress::Started { .. }) => MAX_OUTPUT,
                1 => return Err(invalid("Elevation output before verified command start")),
                _ => return Err(invalid("Unknown elevation frame kind")),
            };
            if frame.len() < HEADER { break; }
            let size = u32::from_be_bytes(frame[1..HEADER].try_into().expect("four-byte length")) as usize;
            if size == 0 || size > limit {
                return Err(invalid("Elevation frame exceeds its byte budget"));
            }
            let end = HEADER + size;
            if frame.len() < end { break; }
            if frame[0] == 1 {
                output.extend_from_slice(&frame[HEADER..end]);
            } else {
                let receipt: Receipt = serde_json::from_slice(&frame[HEADER..end])
                    .map_err(|_| invalid("Malformed elevation receipt"))?;
                let (version, nonce) = match &receipt {
                    Receipt::ConsentPending { version, nonce }
                    | Receipt::Started { version, nonce, .. }
                    | Receipt::Failed { version, nonce, .. }
                    | Receipt::Completed { version, nonce, .. } => (*version, nonce),
                };
                if version != 1 || nonce != &self.nonce {
                    return Err(invalid("Uncorrelated elevation receipt"));
                }
                self.progress = match receipt {
                    Receipt::ConsentPending { .. } if self.progress == Progress::Preparing =>
                        Progress::AwaitingConsent,
                    Receipt::Started { command_pid, elevated: true, .. }
                        if self.progress == Progress::AwaitingConsent && command_pid > 0 =>
                        Progress::Started { command_pid },
                    Receipt::Failed { stage, win32_error, .. }
                        if matches!(self.progress, Progress::Preparing | Progress::AwaitingConsent)
                            && !stage.is_empty() && stage.len() <= 80
                            && stage.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_') =>
                        Progress::Failed { stage, win32_error },
                    Receipt::Completed { command_pid, exit_code, error, win32_error, .. }
                        if matches!(self.progress, Progress::Started { command_pid: started_pid } if started_pid == command_pid)
                            && (exit_code.is_some() || error.as_ref().is_some_and(|message| !message.is_empty()))
                            && error.as_ref().is_none_or(|message| !message.is_empty())
                            && (win32_error.is_none() || error.is_some()) =>
                        Progress::Completed { command_pid, exit_code, error, win32_error },
                    _ => return Err(invalid("Invalid elevation receipt transition")),
                };
            }
            consumed += end;
        }
        // Drain once: many small frames in a single read must not trigger a
        // quadratic series of buffer shifts.
        self.buffer.drain(..consumed);
        Ok(output)
    }

    pub(super) fn eof(&self) -> io::Result<()> {
        if !self.poisoned && self.buffer.is_empty() && self.terminal() {
            Ok(())
        } else {
            Err(invalid("Elevation stream ended without a complete terminal receipt"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn pending() -> Vec<u8> {
        receipt_frame(&Receipt::ConsentPending { version: 1, nonce: NONCE.into() }).unwrap()
    }
    fn started() -> Vec<u8> {
        receipt_frame(&Receipt::Started { version: 1, nonce: NONCE.into(), command_pid: 123, elevated: true }).unwrap()
    }
    fn completed() -> Vec<u8> {
        receipt_frame(&Receipt::Completed { version: 1, nonce: NONCE.into(), command_pid: 123,
            exit_code: Some(7), error: None, win32_error: None }).unwrap()
    }
    fn request() -> Request {
        Request { version: 1, nonce: NONCE.into(), executable: "C:\\Windows\\System32\\cmd.exe".encode_utf16().collect(),
            command: "\"C:\\Windows\\System32\\cmd.exe\" /D /C exit 7\0".encode_utf16().collect(),
            cwd: "C:\\work".encode_utf16().collect(), visible: false }
    }

    #[test]
    fn correlated_receipts_are_removed_before_literal_command_output() {
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        let mut wire = pending(); wire.extend(started());
        wire.extend(output_frame(b"plain stdout\0{\"event\":\"failed\"}\xff").unwrap());
        wire.extend(completed());
        let mut output = Vec::new();
        for chunk in wire.chunks(3) { output.extend(decoder.feed(chunk).unwrap()); }
        assert_eq!(output, b"plain stdout\0{\"event\":\"failed\"}\xff");
        assert_eq!(decoder.progress, Progress::Completed { command_pid: 123, exit_code: Some(7), error: None, win32_error: None });
        decoder.eof().unwrap();
    }

    #[test]
    fn pending_consent_is_distinct_from_command_creation() {
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        assert_eq!(decoder.progress, Progress::Preparing);
        assert!(decoder.feed(&pending()).unwrap().is_empty());
        assert_eq!(decoder.progress, Progress::AwaitingConsent);
        assert!(decoder.eof().is_err());
    }

    #[test]
    fn uac_cancellation_preserves_the_native_error_without_claiming_a_command() {
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        decoder.feed(&pending()).unwrap();
        let failure = Receipt::Failed { version: 1, nonce: NONCE.into(), stage: "UAC_REQUEST".into(), win32_error: Some(1223) };
        assert!(decoder.feed(&receipt_frame(&failure).unwrap()).unwrap().is_empty());
        assert_eq!(decoder.progress, Progress::Failed { stage: "UAC_REQUEST".into(), win32_error: Some(1223) });
        decoder.eof().unwrap();
    }

    #[test]
    fn receipts_require_correlation_and_a_single_ordered_transition() {
        for receipt in [
            Receipt::ConsentPending { version: 2, nonce: NONCE.into() },
            Receipt::ConsentPending { version: 1, nonce: "00000000000000000000000000000000".into() },
            Receipt::Started { version: 1, nonce: NONCE.into(), command_pid: 0, elevated: true },
            Receipt::Started { version: 1, nonce: NONCE.into(), command_pid: 123, elevated: false },
            Receipt::Failed { version: 1, nonce: NONCE.into(), stage: "x".repeat(100), win32_error: None },
        ] {
            let mut decoder = Decoder::new(NONCE.into()).unwrap();
            assert!(decoder.feed(&receipt_frame(&receipt).unwrap()).is_err());
        }
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        assert!(decoder.feed(&started()).is_err());
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        decoder.feed(&pending()).unwrap();
        assert!(decoder.feed(&pending()).is_err());
    }

    #[test]
    fn partial_oversized_unknown_and_trailing_json_headers_fail_closed() {
        for body in [b"{}".to_vec(),
            format!("{{\"event\":\"consent_pending\",\"version\":1,\"nonce\":\"{NONCE}\",\"extra\":1}}").into_bytes(),
            format!("{{\"event\":\"consent_pending\",\"version\":1,\"nonce\":\"{NONCE}\"}}{{}}").into_bytes(),
        ] {
            let mut wire = vec![0]; wire.extend((body.len() as u32).to_be_bytes()); wire.extend(body);
            assert!(Decoder::new(NONCE.into()).unwrap().feed(&wire).is_err());
        }
        for size in [0u32, (MAX_RECEIPT + 1) as u32, u32::MAX] {
            let mut wire = vec![0]; wire.extend(size.to_be_bytes());
            assert!(Decoder::new(NONCE.into()).unwrap().feed(&wire).is_err());
        }
        for length in [0, 1, 3, pending().len() - 1] {
            let mut decoder = Decoder::new(NONCE.into()).unwrap();
            decoder.feed(&pending()[..length]).unwrap();
            assert!(decoder.eof().is_err());
        }
    }

    #[test]
    fn command_output_cannot_forge_completion_and_truncated_relay_is_incomplete() {
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        decoder.feed(&pending()).unwrap(); decoder.feed(&started()).unwrap();
        assert_eq!(decoder.feed(&output_frame(&completed()).unwrap()).unwrap(), completed());
        assert_eq!(decoder.progress, Progress::Started { command_pid: 123 });
        assert!(decoder.eof().is_err());
        decoder.feed(&completed()).unwrap(); decoder.eof().unwrap();
        assert!(decoder.feed(&output_frame(b"late output").unwrap()).is_err());
        assert!(Decoder::new(NONCE.into()).unwrap().feed(&completed()).is_err());
        assert!(Decoder::new(NONCE.into()).unwrap().feed(&output_frame(b"early output").unwrap()).is_err());
        assert!(output_frame(&vec![0;65_537]).is_err());
    }

    #[test]
    fn rejects_unknown_kind_and_phase_invalid_header_immediately() {
        for kind in [2u8, 255] {
            let mut decoder = Decoder::new(NONCE.into()).unwrap();
            assert!(decoder.feed(&[kind]).is_err());
            assert!(decoder.feed(&pending()).is_err());
            assert!(decoder.eof().is_err());
        }
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        assert!(decoder.feed(&[1, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn output_boundary_and_split_headers_stay_framed() {
        let payload = vec![0xa5; 65_536];
        let mut wire = pending();
        wire.extend(started());
        wire.extend(output_frame(&payload).unwrap());
        wire.extend(completed());
        for chunk_size in [1, 4, 5, 8192, 65_536] {
            let mut decoder = Decoder::new(NONCE.into()).unwrap();
            let mut output = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                output.extend(decoder.feed(chunk).unwrap());
            }
            assert_eq!(output, payload);
            decoder.eof().unwrap();
        }
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        decoder.feed(&pending()).unwrap();
        decoder.feed(&started()).unwrap();
        for size in [0u32, 65_537, u32::MAX] {
            let mut bad = Decoder::new(NONCE.into()).unwrap();
            bad.feed(&pending()).unwrap();
            bad.feed(&started()).unwrap();
            let mut header = vec![1];
            header.extend(size.to_be_bytes());
            assert!(bad.feed(&header).is_err());
            assert!(bad.eof().is_err());
        }
        assert!(decoder.feed(&output_frame(b"witness").unwrap()[..6]).unwrap().is_empty());
        assert!(decoder.eof().is_err());
    }

    #[test]
    fn terminal_receipts_are_correlated_and_no_trailing_data_is_accepted() {
        let invalid_receipts = [
            Receipt::Completed { version: 1, nonce: NONCE.into(), command_pid: 124, exit_code: Some(7), error: None, win32_error: None },
            Receipt::Completed { version: 2, nonce: NONCE.into(), command_pid: 123, exit_code: Some(7), error: None, win32_error: None },
            Receipt::Completed { version: 1, nonce: "f".repeat(32), command_pid: 123, exit_code: Some(7), error: None, win32_error: None },
            Receipt::Failed { version: 1, nonce: NONCE.into(), stage: "LATE_FAILURE".into(), win32_error: None },
        ];
        for receipt in invalid_receipts {
            let mut decoder = Decoder::new(NONCE.into()).unwrap();
            decoder.feed(&pending()).unwrap();
            decoder.feed(&started()).unwrap();
            assert!(decoder.feed(&receipt_frame(&receipt).unwrap()).is_err());
            assert!(decoder.feed(&completed()).is_err());
            assert!(decoder.eof().is_err());
        }
        for trailing in [vec![0], vec![1], completed(), output_frame(b"late").unwrap()] {
            let mut decoder = Decoder::new(NONCE.into()).unwrap();
            let mut wire = pending(); wire.extend(started()); wire.extend(completed());
            wire.extend(trailing);
            assert!(decoder.feed(&wire).is_err());
            assert!(decoder.eof().is_err());
        }
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        decoder.feed(&pending()).unwrap();
        decoder.feed(&started()).unwrap();
        decoder.feed(&completed()).unwrap();
        decoder.eof().unwrap();
        assert!(decoder.feed(&[0]).is_err());
        assert!(decoder.eof().is_err());
    }

    #[test]
    fn failure_before_start_is_terminal_and_cannot_carry_output() {
        let failure = receipt_frame(&Receipt::Failed { version: 1, nonce: NONCE.into(),
            stage: "BROKER_SETUP".into(), win32_error: Some(5) }).unwrap();
        let mut decoder = Decoder::new(NONCE.into()).unwrap();
        assert!(decoder.feed(&failure).unwrap().is_empty());
        decoder.eof().unwrap();
        assert!(decoder.feed(&output_frame(b"unexpected").unwrap()).is_err());
        assert!(decoder.eof().is_err());
    }

    #[test]
    fn elevation_request_refuses_relative_device_and_ambiguous_paths() {
        for path in [r"tool.exe", r"C:tool.exe", r"\tool.exe", r"\\server\share\tool.exe",
            r"\\?\C:\tool.exe", r"C:\dir\..\tool.exe", r"C:\dir.\tool.exe",
            r"C:\dir\tool.exe:stream", r"C:\dir\NUL.exe", r"C:\dir\tool.exe "] {
            let mut bad=request(); bad.executable=path.encode_utf16().collect();
            assert!(bad.validate(NONCE).is_err(), "unsafe executable spelling: {path}");
            let mut bad=request(); bad.cwd=path.encode_utf16().collect();
            assert!(bad.validate(NONCE).is_err(), "unsafe cwd spelling: {path}");
        }
        let mut bad=request(); bad.executable=vec![67,58,92,0xd800];
        assert!(bad.validate(NONCE).is_err(), "unpaired UTF-16 is not displayable");
        let mut bad=request(); bad.command=vec![0xd800,0];
        assert!(bad.validate(NONCE).is_err(), "unpaired UTF-16 command is not displayable");
        let mut good=request();good.executable=r"C:\École\program.exe".encode_utf16().collect();
        good.validate(NONCE).unwrap();
    }

    #[test]
    fn launch_request_is_bounded_and_preserves_exact_utf16_command() {
        let good = request(); good.validate(NONCE).unwrap();
        let encoded = frame(&good, MAX_REQUEST).unwrap();
        let copy: Request = serde_json::from_slice(&encoded[4..]).unwrap();
        assert_eq!(copy.command, good.command);
        let mut bad = request(); bad.version = 2; assert!(bad.validate(NONCE).is_err());
        let mut bad = request(); bad.nonce = "0".repeat(32); assert!(bad.validate(NONCE).is_err());
        let mut bad = request(); bad.command = vec![65,0,66,0]; assert!(bad.validate(NONCE).is_err());
        let mut bad = request(); bad.command.pop(); assert!(bad.validate(NONCE).is_err());
        let mut bad = request(); bad.command = vec![65;32768]; bad.command.push(0); assert!(bad.validate(NONCE).is_err());
        let mut bad = request(); bad.cwd.push(0); assert!(bad.validate(NONCE).is_err());
        assert!(frame(&"oversized", 3).is_err());
    }
}
