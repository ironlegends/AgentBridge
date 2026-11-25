//! Bounded PNG encoder for pixels obtained from an owned XComposite pixmap.
//! Never reads the root drawable or a screen crop.
use super::*;

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 { crc = (crc >> 1) ^ (0xedb88320u32 & 0u32.wrapping_sub(crc & 1)); }
    }
    !crc
}
fn chunk(output: &mut Vec<u8>, kind: &[u8; 4], bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(kind);
    output.extend_from_slice(bytes);
    let offset = output.len() - bytes.len() - 4;
    let crc = crc32(&output[offset..]);
    output.extend_from_slice(&crc.to_be_bytes());
}
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for part in bytes.chunks(3) {
        let a = part[0]; let b = *part.get(1).unwrap_or(&0); let c = *part.get(2).unwrap_or(&0);
        out.push(ABC[(a >> 2) as usize] as char);
        out.push(ABC[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if part.len() > 1 { ABC[(((b & 15) << 2) | (c >> 6)) as usize] as char } else { '=' });
        out.push(if part.len() > 2 { ABC[(c & 63) as usize] as char } else { '=' });
    }
    out
}

// Screenshots travel inside a JSON string in the tool's text result. Limit the
// escaped tree to 256 KiB and the stored PNG to 512 x 360 (under 740 KB in
// base64), leaving room in the 1 MiB reply for window, action and RPC fields.
pub(super) fn bound_screenshot_tree(elements: &mut Vec<Value>) {
    let mut used = 0;
    let count = elements.iter().take_while(|element| {
        // Include both layers of JSON escaping, plus the array separator.
        used += serde_json::to_string(&element.to_string()).expect("serializable text").len() + 1;
        used <= 256 * 1024
    }).count();
    elements.truncate(count);
}

pub(super) fn png(width: usize, height: usize, rgb: &[u8]) -> io::Result<Value> {
    if width == 0 || height == 0 || width > 4096 || height > 4096
        || rgb.len() != width * height * 3 { return Err(error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED")); }
    let scale = (512.0 / width as f64).min(360.0 / height as f64).min(1.0);
    let w = ((width as f64 * scale) as usize).max(1);
    let h = ((height as f64 * scale) as usize).max(1);
    let mut filtered = Vec::with_capacity((w * 3 + 1) * h);
    for y in 0..h {
        filtered.push(0);
        for x in 0..w {
            let index = ((y * height / h) * width + x * width / w) * 3;
            filtered.extend_from_slice(&rgb[index..index + 3]);
        }
    }
    let mut zlib = vec![0x78, 0x01];
    for (index, part) in filtered.chunks(65535).enumerate() {
        zlib.push(u8::from(index == (filtered.len() - 1) / 65535));
        let length = part.len() as u16;
        zlib.extend_from_slice(&length.to_le_bytes());
        zlib.extend_from_slice(&(!length).to_le_bytes());
        zlib.extend_from_slice(part);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &filtered { a = (a + u32::from(*byte)) % 65521; b = (b + a) % 65521; }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = [0u8; 13];
    header[..4].copy_from_slice(&(w as u32).to_be_bytes());
    header[4..8].copy_from_slice(&(h as u32).to_be_bytes());
    header[8] = 8; header[9] = 2;
    chunk(&mut bytes, b"IHDR", &header);
    chunk(&mut bytes, b"IDAT", &zlib);
    chunk(&mut bytes, b"IEND", &[]);
    Ok(json!({"mime_type":"image/png","data_base64":base64(&bytes),"width":w,"height":h,
        "scope":"selected_window","source":"xcomposite_named_window_pixmap"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn png_rejects_mismatched_buffers_and_encodes_known_pixel() {
        assert!(png(0, 1, &[]).is_err());
        assert!(png(1, 1, &[1, 2]).is_err());
        let value = png(1, 1, &[255, 0, 0]).unwrap();
        assert_eq!(value["width"], 1);
        assert_eq!(value["height"], 1);
        assert!(value["data_base64"].as_str().unwrap().starts_with("iVBORw0KGgo"));
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
        assert_eq!(base64(&[255, 0, 0]), "/wAA");
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;

    struct CapturedFixture {
        width: usize,
        height: usize,
        capture: Option<NativeSnapshot>,
    }

    impl Backend for CapturedFixture {
        fn inspect(&mut self) -> io::Result<NativeWindow> {
            Ok(NativeWindow { identity: "selected".into(), x: -32768, y: -32768,
                width: self.width as u64, height: self.height as u64, enabled: true })
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities { backend: "x11_scoped_events", tree: "x11_window_tree_not_accessibility",
                actions: &["wait", "click", "send_keys"], screenshot: true }
        }
        fn snapshot(&mut self, _: SnapshotOptions) -> io::Result<NativeSnapshot> {
            Ok(self.capture.take().unwrap())
        }
        fn confirm(&mut self, _: &DedicatedWindow) -> io::Result<()> { unreachable!() }
        fn action(&mut self, _: &Action) -> io::Result<Value> { unreachable!() }
    }

    #[test]
    fn selected_window_image_and_tree_fit_the_json_rpc_response() {
        use agent_bridge_gateway::{JsonRpcId, JsonRpcResponse};

        for (width, height) in [(800, 600), (2048, 1536), (1024, 720)] {
            let mut seed = 7u32;
            let pixels: Vec<u8> = (0..width * height * 3).map(|_| {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                (seed >> 24) as u8
            }).collect();
            let mut elements: Vec<_> = (0..200).map(|i| json!({
                "ref":format!("control:{}", i + 1), "role":"x11_window",
                "name":if width > 800 { "\\\"".repeat(512) } else { format!("Document section {i}") },
                "class_name":"Editor",
                "x":0,"y":0,"width":width,"height":height,"supports_click":true,
                "supports_send_keys":true,"synthetic_events_may_be_ignored":true
            })).collect();
            bound_screenshot_tree(&mut elements);
            if width == 800 { assert_eq!(elements.len(), 200); }
            else { assert!(!elements.is_empty() && elements.len() < 200); }
            let image = png(width, height, &pixels).unwrap();
            if width == 1024 {
                assert_eq!((image["width"].as_u64(), image["height"].as_u64()), (Some(512), Some(360)));
            }
            let window_id = "00000000-0000-4000-8000-000000000001";
            let mut selection = DedicatedWindow { desktop_name: "fixture".into(),
                title: "Editor".into(), class_name: "Editor".into(), executable: std::env::current_exe().unwrap() };
            if width == 1024 {
                // Exercise the validated byte ceilings and maximum JSON escaping.
                selection.title = "\\\"".repeat(128);
                selection.class_name = selection.title.clone();
                let cwd = std::env::current_dir().unwrap();
                let root = cwd.ancestors().last().unwrap();
                selection.executable = root.join("\u{1}".repeat(4096 - root.to_str().unwrap().len()));
                assert_eq!(selection.executable.to_str().unwrap().len(), 4096);
            }
            selection.validate().unwrap();
            let capture = NativeSnapshot { truncated: elements.len() < 200, elements, screenshot: Some(image),
                screenshot_status: "captured_selected_window_pixmap" };
            let mut session = Session { selection, approved_identity: "selected".into(), ticket: None,
                observation: None, backend: Box::new(CapturedFixture { width, height, capture: Some(capture) }) };
            let snapshot = session.render(window_id, SnapshotOptions {
                tree: true, screenshot: true, interactive: true, maximum: 200,
            }).unwrap();
            let result = serde_json::to_value(tool_result(Ok(snapshot))).unwrap();
            let reply = JsonRpcResponse::success(JsonRpcId::String(window_id.into()), result);
            let bytes = serde_json::to_string(&reply).unwrap().len();
            println!("{width}x{height} serialized response: {bytes} bytes");
            assert!(bytes <= 1024 * 1024, "{width}x{height} response was {bytes} bytes");
        }
    }
}
