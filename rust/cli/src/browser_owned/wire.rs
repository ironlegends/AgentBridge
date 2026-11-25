use std::io;

pub(super) struct FrameDecoder {
    limit: usize,
    header: [u8; 4],
    header_len: usize,
    expected: Option<usize>,
    body: Vec<u8>,
    complete: bool,
    failed: bool,
}
impl FrameDecoder {
    pub(super) fn new(limit: usize) -> Self {
        Self { limit, header: [0; 4], header_len: 0, expected: None,
            body: Vec::new(), complete: false, failed: false }
    }
    fn invalid(&mut self, message: &'static str) -> io::Error {
        self.failed = true;
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
    pub(super) fn push(&mut self, mut input: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if self.failed || (self.complete && !input.is_empty()) {
            return Err(self.invalid("unsolicited or invalid worker bytes"));
        }
        if self.complete || input.is_empty() { return Ok(None); }
        if self.header_len < 4 {
            let take = (4 - self.header_len).min(input.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&input[..take]);
            self.header_len += take;
            input = &input[take..];
            if self.header_len < 4 { return Ok(None); }
            let length = u32::from_le_bytes(self.header) as usize;
            if length == 0 || length > self.limit {
                return Err(self.invalid("worker reply exceeds the frame budget"));
            }
            self.expected = Some(length);
        }
        let expected = self.expected.expect("validated frame header");
        if input.len() > expected - self.body.len() {
            return Err(self.invalid("unsolicited bytes after worker reply"));
        }
        self.body.extend_from_slice(input);
        if self.body.len() == expected {
            self.complete = true;
            return Ok(Some(std::mem::take(&mut self.body)));
        }
        Ok(None)
    }
    pub(super) fn eof(&self) -> io::Result<()> {
        if self.failed || (!self.complete && self.header_len != 0) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated worker reply"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_private_reply_yields_exactly_one_complete_body() {
        let mut decoder = FrameDecoder::new(1024);
        assert!(decoder.push(&[3, 0]).unwrap().is_none());
        assert!(decoder.push(&[0, 0, b'a']).unwrap().is_none());
        assert_eq!(decoder.push(b"bc").unwrap(), Some(b"abc".to_vec()));
        decoder.eof().unwrap();
    }
    #[test]
    fn oversized_header_is_refused_without_accepting_payload() {
        let mut decoder = FrameDecoder::new(1024);
        assert_eq!(decoder.push(&1025u32.to_le_bytes()).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
    #[test]
    fn partial_eof_and_unsolicited_trailing_bytes_are_protocol_failures() {
        let mut decoder = FrameDecoder::new(1024);
        decoder.push(&[5, 0, 0, 0, b'a']).unwrap();
        assert_eq!(decoder.eof().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        let mut decoder = FrameDecoder::new(1024);
        assert!(decoder.push(&[1, 0, 0, 0, b'a', b'b']).is_err());
    }
}
