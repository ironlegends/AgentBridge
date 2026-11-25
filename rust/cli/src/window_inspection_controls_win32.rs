//! Narrow Win32 control adapter for the exact locally consented work window.
//! No global enumeration, desktop pixels, pointer injection, shell or UIA proxy.
//! WM_PRINT captures just the approved HWND with a bounded message timeout.
use super::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::slice;

const WM_PRINT: u32 = 0x0317;
const WM_GETTEXT: u32 = 0x000D;
const WM_SETTEXT: u32 = 0x000C;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const WM_HSCROLL: u32 = 0x0114;
const WM_VSCROLL: u32 = 0x0115;
const BM_CLICK: u32 = 0x00F5;
const SB_LINEUP: usize = 0;
const SB_LINEDOWN: usize = 1;
const SB_TOP: usize = 6;
const SB_BOTTOM: usize = 7;
const SB_ENDSCROLL: usize = 8;
const WS_VSCROLL: isize = 0x0020_0000;
const WS_HSCROLL: isize = 0x0010_0000;
const MAX_SEND_KEYS_UNITS: usize = 1024;
const VK_BACK: usize = 0x08;
const VK_TAB: usize = 0x09;
const VK_RETURN: usize = 0x0D;
const VK_ESCAPE: usize = 0x1B;
const VK_END: usize = 0x23;
const VK_HOME: usize = 0x24;
const VK_LEFT: usize = 0x25;
const VK_UP: usize = 0x26;
const VK_RIGHT: usize = 0x27;
const VK_DOWN: usize = 0x28;
const VK_DELETE: usize = 0x2E;
const PRF_CHECKVISIBLE: isize = 0x01;
const PRF_NONCLIENT: isize = 0x02;
const PRF_CLIENT: isize = 0x04;
const PRF_CHILDREN: isize = 0x10;
const SMTO_BLOCK: u32 = 0x0001;
const SMTO_ABORTIFHUNG: u32 = 0x0002;
const GWL_STYLE: i32 = -16;
const ES_PASSWORD: isize = 0x0020;
const BI_RGB: u32 = 0;
const DIB_RGB_COLORS: u32 = 0;
const MAX_CAPTURE_WIDTH: i64 = 1920;
const MAX_CAPTURE_HEIGHT: i64 = 1080;
const MAX_PREVIEW_WIDTH: usize = 360;
const MAX_PREVIEW_HEIGHT: usize = 260;

#[link(name="user32")]
extern "system" {
    fn EnumChildWindows(parent: Hwnd, callback: Option<unsafe extern "system" fn(Hwnd, isize) -> i32>, state: isize) -> i32;
    fn IsChild(parent: Hwnd, child: Hwnd) -> i32;
    fn GetParent(child: Hwnd) -> Hwnd;
    fn GetWindowLongPtrW(window: Hwnd, index: i32) -> isize;
    fn SendMessageTimeoutW(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize,
        flags: u32, timeout_ms: u32, result: *mut usize) -> isize;
}
#[link(name="gdi32")]
extern "system" {
    fn CreateCompatibleDC(compatible: Handle) -> Handle;
    fn DeleteDC(dc: Handle) -> i32;
    fn CreateDIBSection(dc: Handle, info: *const BitmapInfo, usage: u32,
        bits: *mut *mut c_void, section: Handle, offset: u32) -> Handle;
    fn SelectObject(dc: Handle, object: Handle) -> Handle;
    fn DeleteObject(object: Handle) -> i32;
}
#[repr(C)]
struct BitmapHeader {
    size: u32, width: i32, height: i32, planes: u16, bit_count: u16,
    compression: u32, image_size: u32, xppm: i32, yppm: i32,
    colors_used: u32, colors_important: u32,
}
#[repr(C)]
struct BitmapInfo { header: BitmapHeader, colors: [u32; 1] }

struct ScreenDc(Handle);
impl Drop for ScreenDc {
    fn drop(&mut self) { if self.0 != 0 { unsafe { DeleteDC(self.0); } } }
}
struct Bitmap(Handle);
impl Drop for Bitmap {
    fn drop(&mut self) { if self.0 != 0 { unsafe { DeleteObject(self.0); } } }
}

#[derive(Clone, Debug)]
pub(crate) struct ControlRef {
    pub(crate) selector: String,
    hwnd: Hwnd,
    parent: Hwnd,
    class_name: String,
    thread_id: u32,
    password: bool,
}

pub(crate) struct Tree {
    pub(crate) nodes: Vec<Value>,
    pub(crate) refs: Vec<ControlRef>,
    pub(crate) truncated: bool,
}

struct EnumContext { hwnds: Vec<Hwnd>, limit: usize, overflow: bool }
unsafe extern "system" fn child_callback(hwnd: Hwnd, ptr: isize) -> i32 {
    if ptr == 0 { return 0; }
    // Only our own short-lived stack allocation is passed as callback state.
    let ctx = unsafe { &mut *(ptr as *mut EnumContext) };
    if ctx.hwnds.len() >= ctx.limit {
        ctx.overflow = true;
        return 0;
    }
    ctx.hwnds.push(hwnd);
    1
}

fn send_bounded(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> io::Result<usize> {
    let mut returned = 0usize;
    // A hung/malicious selected app must not hang the MCP gateway forever.
    let timeout_ms = if msg == WM_GETTEXT { 40 } else { 400 };
    if unsafe { SendMessageTimeoutW(hwnd, msg, wparam, lparam,
        SMTO_BLOCK | SMTO_ABORTIFHUNG, timeout_ms, &mut returned) } == 0 {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "Selected control did not respond"));
    }
    Ok(returned)
}

fn control_label(hwnd: Hwnd, class_name: &str) -> String {
    // Never read editable text, passwords, or arbitrary controls. Only
    // the label of a native Button/Static control is used as a tree name.
    if !matches!(class_name, "Button" | "Static") { return String::new(); }
    let mut label = [0u16; 121];
    if let Ok(count) = send_bounded(hwnd, WM_GETTEXT, label.len(), label.as_mut_ptr() as isize) {
        let len = count.min(120);
        return String::from_utf16_lossy(&label[..len])
            .chars().filter(|c| !c.is_control()).collect();
    }
    String::new()
}

fn type_for_class(name: &str) -> &'static str {
    match name {
        "Button" => "button", "Edit" => "text_box", "Static" => "text",
        "ComboBox" => "combo_box", "ScrollBar" => "scroll_bar",
        "SysListView32" => "list", "SysTreeView32" => "tree",
        "msctls_progress32" => "progress", _ => "win32_control",
    }
}

pub(crate) fn controls(
    selection: &DedicatedWindow, identity: &Identity,
    maximum: usize, interactive_only: bool,
) -> io::Result<Tree> {
    verify_selected_identity(selection, identity)?;
    let mut state = EnumContext { hwnds: Vec::with_capacity(maximum), limit: maximum, overflow: false };
    unsafe {
        EnumChildWindows(identity.hwnd, Some(child_callback), (&mut state as *mut EnumContext) as isize);
    }
    let mut nodes = Vec::with_capacity(state.hwnds.len());
    let mut refs = Vec::with_capacity(state.hwnds.len());
    let mut selectors = HashMap::<Hwnd, String>::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    for hwnd in state.hwnds {
        if Instant::now() >= deadline {
            state.overflow = true;
            break;
        }
        if unsafe { IsWindow(hwnd) } == 0
            || unsafe { IsChild(identity.hwnd, hwnd) } == 0 { continue; }
        let mut pid = 0u32;
        let thread_id = unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
        if pid != identity.process_id || thread_id != identity.thread_id {
            continue;
        }
        let enabled = unsafe { IsWindowEnabled(hwnd) } != 0;
        let visible = unsafe { IsWindowVisible(hwnd) } != 0;
        if interactive_only && (!enabled || !visible) { continue; }
        let Ok(class_name) = window_class(hwnd) else { continue; };
        let parent = unsafe { GetParent(hwnd) };
        let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) };
        let password = class_name == "Edit" && (style & ES_PASSWORD != 0);
        let scrollable = (style & (WS_VSCROLL | WS_HSCROLL) != 0)
            || matches!(class_name.as_str(), "ScrollBar" | "SysListView32" | "SysTreeView32" | "ListBox");
        let selector = format!("control:{}", refs.len() + 1);
        let parent_selector = selectors.get(&parent).cloned()
            .unwrap_or_else(|| "window".into());
        let mut bounds = Rect::default();
        let rect_ok = unsafe { GetWindowRect(hwnd, &mut bounds) } != 0;
        let mut supported: Vec<&str> = match class_name.as_str() {
            "Button" if enabled && visible => vec!["invoke"],
            "Edit" if enabled && visible && !password => vec!["set_value", "send_keys"],
            _ => Vec::new(),
        };
        if enabled && visible && !password && scrollable {
            supported.push("scroll");
        }
        nodes.push(json!({
            "selector":selector,
            "parent":parent_selector,
            "class_name":class_name,
            "control_type":type_for_class(&class_name),
            "name":control_label(hwnd, &class_name),
            "visible":visible, "enabled":enabled,
            "bounds": if rect_ok { json!({
                "x":bounds.left,"y":bounds.top,
                "width":i64::from(bounds.right)-i64::from(bounds.left),
                "height":i64::from(bounds.bottom)-i64::from(bounds.top)
            }) } else { Value::Null },
            "supported_actions":supported,
        }));
        selectors.insert(hwnd, selector.clone());
        refs.push(ControlRef {selector,hwnd,parent,class_name,thread_id,password});
    }
    verify_selected_identity(selection, identity)?;
    Ok(Tree { nodes, refs, truncated: state.overflow })
}

fn validated_control<'a>(
    selection: &DedicatedWindow, identity: &Identity,
    refs: &'a [ControlRef], selector: &str,
) -> io::Result<&'a ControlRef> {
    verify_selected_identity(selection, identity)?;
    let target = refs.iter().find(|r| r.selector == selector)
        .ok_or_else(denied)?;
    if unsafe { IsWindow(target.hwnd) } == 0
        || unsafe { IsChild(identity.hwnd, target.hwnd) } == 0
        || unsafe { GetParent(target.hwnd) } != target.parent
        || unsafe { IsWindowEnabled(target.hwnd) } == 0
        || unsafe { IsWindowVisible(target.hwnd) } == 0
        || window_class(target.hwnd)? != target.class_name {
        return Err(denied());
    }
    let mut pid = 0u32;
    let tid = unsafe { GetWindowThreadProcessId(target.hwnd, &mut pid) };
    if pid != identity.process_id || tid != target.thread_id || tid != identity.thread_id {
        return Err(denied());
    }
    if target.password || (target.class_name == "Edit"
        && unsafe { GetWindowLongPtrW(target.hwnd, GWL_STYLE) } & ES_PASSWORD != 0) {
        return Err(denied());
    }
    Ok(target)
}

#[derive(Debug, PartialEq, Eq)]
enum KeyOp {
    Char(u16),
    VKey(usize),
}

fn parse_send_keys(keys: &str, verbatim: bool) -> io::Result<Vec<KeyOp>> {
    if keys.is_empty() || keys.encode_utf16().count() > MAX_SEND_KEYS_UNITS {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Keys length out of bounds"));
    }
    if keys.chars().any(|c| c == '\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL character forbidden"));
    }
    let mut ops = Vec::new();
    if verbatim {
        for ch in keys.chars() {
            if ch.is_control() && !matches!(ch, '\r' | '\n' | '\t') {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Control character forbidden"));
            }
            let mapped = if ch == '\n' { '\r' } else { ch };
            let mut buf = [0u16; 2];
            for unit in mapped.encode_utf16(&mut buf).iter().copied() {
                ops.push(KeyOp::Char(unit));
            }
        }
        return Ok(ops);
    }
    let chars: Vec<char> = keys.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '{' {
            let mut end = i + 1;
            while end < chars.len() && chars[end] != '}' {
                end += 1;
            }
            if end >= chars.len() || end == i + 1 || end - i > 24 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid key token"));
            }
            let token: String = chars[i + 1..end].iter().collect();
            let upper = token.to_ascii_uppercase();
            match upper.as_str() {
                "ENTER" | "RETURN" => ops.push(KeyOp::Char(VK_RETURN as u16)),
                "TAB" => ops.push(KeyOp::Char(VK_TAB as u16)),
                "BACKSPACE" | "BS" | "BACK" => ops.push(KeyOp::Char(VK_BACK as u16)),
                "ESC" | "ESCAPE" => ops.push(KeyOp::VKey(VK_ESCAPE)),
                "DEL" | "DELETE" => ops.push(KeyOp::VKey(VK_DELETE)),
                "HOME" => ops.push(KeyOp::VKey(VK_HOME)),
                "END" => ops.push(KeyOp::VKey(VK_END)),
                "LEFT" => ops.push(KeyOp::VKey(VK_LEFT)),
                "RIGHT" => ops.push(KeyOp::VKey(VK_RIGHT)),
                "UP" => ops.push(KeyOp::VKey(VK_UP)),
                "DOWN" => ops.push(KeyOp::VKey(VK_DOWN)),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Unsupported or modifier key token",
                    ));
                }
            }
            i = end + 1;
            continue;
        }
        if ch.is_control() && !matches!(ch, '\r' | '\n' | '\t') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Control character forbidden"));
        }
        let mapped = if ch == '\n' { '\r' } else { ch };
        let mut buf = [0u16; 2];
        for unit in mapped.encode_utf16(&mut buf).iter().copied() {
            ops.push(KeyOp::Char(unit));
        }
        i += 1;
    }
    Ok(ops)
}

fn scroll_message(direction: Option<&str>, to: Option<&str>) -> io::Result<(u32, usize)> {
    match (direction, to) {
        (Some("up"), None) => Ok((WM_VSCROLL, SB_LINEUP)),
        (Some("down"), None) => Ok((WM_VSCROLL, SB_LINEDOWN)),
        (Some("left"), None) => Ok((WM_HSCROLL, SB_LINEUP)),
        (Some("right"), None) => Ok((WM_HSCROLL, SB_LINEDOWN)),
        (None, Some("top")) => Ok((WM_VSCROLL, SB_TOP)),
        (None, Some("bottom")) => Ok((WM_VSCROLL, SB_BOTTOM)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Specify direction or to")),
    }
}

fn is_scrollable_hwnd(hwnd: Hwnd, class_name: &str, msg: u32) -> bool {
    let style = unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) };
    let needed = if msg == WM_HSCROLL { WS_HSCROLL } else { WS_VSCROLL };
    (style & needed != 0)
        || matches!(class_name, "ScrollBar" | "SysListView32" | "SysTreeView32" | "ListBox")
}

fn dispatch_invoke_hwnd(hwnd: Hwnd) -> io::Result<()> {
    send_bounded(hwnd, BM_CLICK, 0, 0)?;
    Ok(())
}

fn dispatch_set_value_hwnd(hwnd: Hwnd, input: &str) -> io::Result<()> {
    if unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } & ES_PASSWORD != 0 {
        return Err(denied());
    }
    if input.encode_utf16().count() > 4096 || input.chars().any(|c| c == '\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Value exceeds control limit"));
    }
    let wide: Vec<u16> = input.encode_utf16().chain(std::iter::once(0)).collect();
    if send_bounded(hwnd, WM_SETTEXT, 0, wide.as_ptr() as isize)? == 0 {
        return Err(denied());
    }
    Ok(())
}

fn dispatch_scroll_hwnd(
    hwnd: Hwnd, class_name: &str, direction: Option<&str>, to: Option<&str>,
) -> io::Result<()> {
    let (msg, code) = scroll_message(direction, to)?;
    if !is_scrollable_hwnd(hwnd, class_name, msg) {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "semantic_scroll_unavailable"));
    }
    send_bounded(hwnd, msg, code, 0)?;
    send_bounded(hwnd, msg, SB_ENDSCROLL, 0)?;
    Ok(())
}

fn dispatch_send_keys_hwnd(hwnd: Hwnd, keys: &str, verbatim: bool) -> io::Result<()> {
    if unsafe { GetWindowLongPtrW(hwnd, GWL_STYLE) } & ES_PASSWORD != 0 {
        return Err(denied());
    }
    let ops = parse_send_keys(keys, verbatim)?;
    for op in ops {
        match op {
            KeyOp::Char(unit) => {
                send_bounded(hwnd, WM_CHAR, usize::from(unit), 1)?;
            }
            KeyOp::VKey(vk) => {
                send_bounded(hwnd, WM_KEYDOWN, vk, 1)?;
                send_bounded(hwnd, WM_KEYUP, vk, 1)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn act(
    selection: &DedicatedWindow, identity: &Identity,
    refs: &[ControlRef], selector: &str,
    action: &str, value: Option<&str>,
) -> io::Result<()> {
    let target = validated_control(selection, identity, refs, selector)?;
    match (action, target.class_name.as_str()) {
        ("invoke", "Button") if value.is_none() => dispatch_invoke_hwnd(target.hwnd)?,
        ("set_value", "Edit") => {
            let input = value.ok_or_else(denied)?;
            dispatch_set_value_hwnd(target.hwnd, input)?;
        }
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported,
            "Semantic action not available for this control")),
    }
    // One-time observation is already consumed in the caller. No fresh action
    // capability can be minted until the exact approved window is reobserved.
    Ok(())
}

pub(crate) fn scroll(
    selection: &DedicatedWindow, identity: &Identity,
    refs: &[ControlRef], selector: Option<&str>,
    direction: Option<&str>, to: Option<&str>,
) -> io::Result<()> {
    let (hwnd, class_name) = if let Some(sel) = selector {
        let target = validated_control(selection, identity, refs, sel)?;
        (target.hwnd, target.class_name.clone())
    } else {
        verify_selected_identity(selection, identity)?;
        (identity.hwnd, window_class(identity.hwnd)?)
    };
    dispatch_scroll_hwnd(hwnd, &class_name, direction, to)
}

pub(crate) fn send_keys(
    selection: &DedicatedWindow, identity: &Identity,
    refs: &[ControlRef], selector: &str,
    keys: &str, verbatim: bool,
) -> io::Result<()> {
    let target = validated_control(selection, identity, refs, selector)?;
    if target.class_name != "Edit" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Post-message send_keys is only available on non-password Edit controls",
        ));
    }
    dispatch_send_keys_hwnd(target.hwnd, keys, verbatim)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (if crc & 1 != 0 { 0xedb8_8320 } else { 0 });
        }
    }
    !crc
}
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32,0u32);
    for &v in data {
        a = (a + u32::from(v)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}
fn png_chunk(data: &mut Vec<u8>, kind: &[u8;4], bytes: &[u8]) {
    data.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    data.extend_from_slice(kind);
    data.extend_from_slice(bytes);
    let mut crc_data=Vec::with_capacity(bytes.len()+4);
    crc_data.extend_from_slice(kind);
    crc_data.extend_from_slice(bytes);
    data.extend_from_slice(&crc32(&crc_data).to_be_bytes());
}
fn png_rgb(width: usize, height: usize, bgra: &[u8], source_width:usize, source_height:usize) -> Vec<u8> {
    let mut rgb = Vec::with_capacity((width*3+1)*height);
    for y in 0..height {
        rgb.push(0); // PNG filter none
        let sy = y * source_height / height;
        for x in 0..width {
            let sx = x * source_width / width;
            let src = (sy * source_width + sx) * 4;
            rgb.extend_from_slice(&[bgra[src+2], bgra[src+1], bgra[src]]);
        }
    }
    let mut compressed = Vec::with_capacity(rgb.len()+64);
    compressed.extend_from_slice(&[0x78,0x01]); // zlib DEFLATE, stored blocks
    for (index, chunk) in rgb.chunks(65535).enumerate() {
        let final_block = index == (rgb.len()-1)/65535;
        compressed.push(if final_block {1} else {0});
        let size=chunk.len() as u16;
        compressed.extend_from_slice(&size.to_le_bytes());
        compressed.extend_from_slice(&(!size).to_le_bytes());
        compressed.extend_from_slice(chunk);
    }
    compressed.extend_from_slice(&adler32(&rgb).to_be_bytes());
    let mut png=Vec::with_capacity(compressed.len()+100);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr=[0u8;13];
    ihdr[..4].copy_from_slice(&(width as u32).to_be_bytes());
    ihdr[4..8].copy_from_slice(&(height as u32).to_be_bytes());
    ihdr[8]=8;ihdr[9]=2; // 8-bit RGB
    png_chunk(&mut png,b"IHDR",&ihdr);
    png_chunk(&mut png,b"IDAT",&compressed);
    png_chunk(&mut png,b"IEND",&[]);
    png
}
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out=String::with_capacity(bytes.len().div_ceil(3)*4);
    for chunk in bytes.chunks(3) {
        let a=chunk[0];let b=*chunk.get(1).unwrap_or(&0);let c=*chunk.get(2).unwrap_or(&0);
        out.push(ABC[(a>>2) as usize] as char);
        out.push(ABC[(((a&3)<<4)|(b>>4)) as usize] as char);
        out.push(if chunk.len()>1 {ABC[(((b&15)<<2)|(c>>6)) as usize] as char} else {'='});
        out.push(if chunk.len()>2 {ABC[(c&63) as usize] as char} else {'='});
    }
    out
}

pub(crate) fn screenshot(
    selection: &DedicatedWindow, identity: &Identity,
) -> io::Result<(String,usize,usize)> {
    let before = observe_window(selection, identity.hwnd, true)?;
    if before.identity != *identity
        || before.width > MAX_CAPTURE_WIDTH || before.height > MAX_CAPTURE_HEIGHT {
        return Err(denied());
    }
    let (w,h)=(before.width as usize,before.height as usize);
    let dc = ScreenDc(unsafe { CreateCompatibleDC(0) });
    if dc.0 == 0 { return Err(denied()); }
    let header = BitmapHeader { size: size_of::<BitmapHeader>() as u32,
        width:w as i32,height:-(h as i32),planes:1,bit_count:32,
        compression:BI_RGB,image_size:(w*h*4) as u32,
        xppm:0,yppm:0,colors_used:0,colors_important:0 };
    let info=BitmapInfo {header,colors:[0]};
    let mut bits: *mut c_void=ptr::null_mut();
    let bmp = Bitmap(unsafe {
        CreateDIBSection(dc.0,&info,DIB_RGB_COLORS,&mut bits,0,0)
    });
    if bmp.0 == 0 || bits.is_null() { return Err(denied()); }
    // GDI does not promise initialized DIB pixels. Never return unpainted
    // buffer bytes if the selected application handles WM_PRINT incompletely.
    unsafe { ptr::write_bytes(bits.cast::<u8>(), 0, w * h * 4); }
    let previous=unsafe {SelectObject(dc.0,bmp.0)};
    if previous==0 || previous == -1 { return Err(denied()); }
    let paint = send_bounded(identity.hwnd,WM_PRINT,dc.0 as usize,
        PRF_CLIENT|PRF_NONCLIENT|PRF_CHILDREN|PRF_CHECKVISIBLE);
    // Restore before bitmap destruction. Never BitBlt screen/other windows.
    unsafe { SelectObject(dc.0,previous); }
    paint?;
    let after=observe_window(selection,identity.hwnd,true)?;
    if after.identity != *identity || after.width != before.width || after.height != before.height {
        return Err(denied());
    }
    let raw=unsafe {slice::from_raw_parts(bits as *const u8,w*h*4)};
    if raw.iter().all(|&pixel| pixel == 0) {
        return Err(io::Error::new(io::ErrorKind::Unsupported,
            "Selected window does not implement a renderable WM_PRINT"));
    }
    let scale=(MAX_PREVIEW_WIDTH as f64 / w as f64)
        .min(MAX_PREVIEW_HEIGHT as f64 / h as f64).min(1.0);
    let out_width=((w as f64*scale).floor() as usize).max(1);
    let out_height=((h as f64*scale).floor() as usize).max(1);
    let png=png_rgb(out_width,out_height,raw,w,h);
    Ok((base64(&png),out_width,out_height))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HWND_MESSAGE: Hwnd = -3;
    const WS_CHILD: u32 = 0x4000_0000;
    const ES_MULTILINE: u32 = 0x0004;
    const ES_AUTOVSCROLL: u32 = 0x0040;
    const EM_GETFIRSTVISIBLELINE: u32 = 0x00CE;
    const BM_GETSTATE: u32 = 0x00F2;

    #[link(name = "user32")]
    extern "system" {
        fn CreateWindowExW(
            ex_style: u32,
            class_name: *const u16,
            window_name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: Hwnd,
            menu: Handle,
            instance: Handle,
            param: *mut c_void,
        ) -> Hwnd;
        fn DestroyWindow(hwnd: Hwnd) -> i32;
    }

    struct OwnedHwnd(Hwnd);
    impl Drop for OwnedHwnd {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe { DestroyWindow(self.0); }
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn create_child(parent: Hwnd, class: &str, text: &str, style: u32, w: i32, h: i32) -> OwnedHwnd {
        let cls = wide(class);
        let txt = wide(text);
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                cls.as_ptr(),
                txt.as_ptr(),
                style,
                0,
                0,
                w,
                h,
                parent,
                0,
                0,
                ptr::null_mut(),
            )
        };
        assert_ne!(hwnd, 0, "CreateWindowExW failed for {class}");
        OwnedHwnd(hwnd)
    }

    fn read_text(hwnd: Hwnd) -> String {
        let mut buf = [0u16; 512];
        let n = send_bounded(hwnd, WM_GETTEXT, buf.len(), buf.as_mut_ptr() as isize).unwrap();
        String::from_utf16_lossy(&buf[..n.min(buf.len())])
    }

    #[test]
    fn win32_message_only_edit_send_keys_set_value_and_password_refusal() {
        let host = create_child(HWND_MESSAGE, "Static", "host", 0, 200, 120);
        let edit = create_child(host.0, "Edit", "", WS_CHILD, 180, 24);
        let secret = create_child(host.0, "Edit", "", WS_CHILD | (ES_PASSWORD as u32), 180, 24);
        let btn = create_child(host.0, "Button", "OK", WS_CHILD, 60, 24);

        // set_value on normal Edit succeeds
        dispatch_set_value_hwnd(edit.0, "hello").expect("set_value");
        assert_eq!(read_text(edit.0), "hello");

        // send_keys with safe editing tokens ({END}, literal text, {BACKSPACE}, {HOME}, {DELETE})
        dispatch_send_keys_hwnd(edit.0, "{END}_ab{BACKSPACE}", false).expect("send_keys tokens");
        assert_eq!(read_text(edit.0), "hello_a");

        dispatch_send_keys_hwnd(edit.0, "{HOME}{DELETE}", false).expect("send_keys home+del");
        assert_eq!(read_text(edit.0), "ello_a");

        // verbatim sends literal braces without interpreting tokens
        dispatch_set_value_hwnd(edit.0, "").unwrap();
        dispatch_send_keys_hwnd(edit.0, "{ENTER}", true).expect("verbatim braces");
        assert_eq!(read_text(edit.0), "{ENTER}");

        // Unsafe / system / modifier tokens rejected fail-closed
        for bad in ["{WIN}", "{ALT+F4}", "{CTRL+C}", "{F4}", "{UNCLOSED", "a\0b"] {
            assert!(
                parse_send_keys(bad, false).is_err(),
                "token must be refused: {bad}"
            );
        }

        // Password Edit control refused for both set_value and send_keys
        assert!(dispatch_set_value_hwnd(secret.0, "topsecret").is_err());
        assert!(dispatch_send_keys_hwnd(secret.0, "abc", true).is_err());
        assert_eq!(read_text(secret.0), "");

        // Button invoke succeeds without error
        dispatch_invoke_hwnd(btn.0).expect("invoke button");
        let _ = send_bounded(btn.0, BM_GETSTATE, 0, 0).expect("button alive");
    }

    #[test]
    fn win32_message_only_semantic_scroll_and_non_scrollable_refusal() {
        let host = create_child(HWND_MESSAGE, "Static", "host", 0, 220, 120);
        let multiline = create_child(
            host.0,
            "Edit",
            "",
            WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | (WS_VSCROLL as u32),
            180,
            40,
        );
        let btn = create_child(host.0, "Button", "Plain", WS_CHILD, 60, 24);

        // Fill enough lines so scrolling actually advances EM_GETFIRSTVISIBLELINE
        let lines = (1..=30).map(|i| format!("Line {i}")).collect::<Vec<_>>().join("\r\n");
        dispatch_set_value_hwnd(multiline.0, &lines).expect("fill multiline");
        let line0 = send_bounded(multiline.0, EM_GETFIRSTVISIBLELINE, 0, 0).unwrap();
        assert_eq!(line0, 0);

        dispatch_scroll_hwnd(multiline.0, "Edit", Some("down"), None).expect("scroll down");
        let line1 = send_bounded(multiline.0, EM_GETFIRSTVISIBLELINE, 0, 0).unwrap();
        assert!(line1 >= 1, "expected scroll down to advance first visible line, got {line1}");

        dispatch_scroll_hwnd(multiline.0, "Edit", None, Some("bottom")).expect("scroll bottom");
        let line_bot = send_bounded(multiline.0, EM_GETFIRSTVISIBLELINE, 0, 0).unwrap();
        assert!(line_bot >= line1, "expected scroll bottom >= {line1}, got {line_bot}");

        dispatch_scroll_hwnd(multiline.0, "Edit", None, Some("top")).expect("scroll top");
        let line_top = send_bounded(multiline.0, EM_GETFIRSTVISIBLELINE, 0, 0).unwrap();
        assert_eq!(line_top, 0);

        // Non-scrollable Button returns Unsupported("semantic_scroll_unavailable")
        let err = dispatch_scroll_hwnd(btn.0, "Button", Some("down"), None)
            .expect_err("non-scrollable button must refuse scroll");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), "semantic_scroll_unavailable");
    }
}
