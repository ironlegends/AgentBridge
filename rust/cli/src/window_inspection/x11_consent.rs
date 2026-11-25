//! The only X11 window this adapter creates is its local consent dialog.
//! No MCP request can select a target or answer the dialog. Synthetic events
//! are ignored and keyboard/default/timeout actions deny permission.
use super::*;

struct Dialog<'a> { connection: &'a XConnection, window: Window, gc: Gcontext, font: Font }
impl Drop for Dialog<'_> {
    fn drop(&mut self) {
        let _ = self.connection.destroy_window(self.window);
        let _ = self.connection.free_gc(self.gc);
        let _ = self.connection.close_font(self.font);
        let _ = self.connection.flush();
    }
}
fn literal(value: &str) -> String {
    value.chars().flat_map(|character|if character.is_ascii_graphic() || character == ' ' {
        character.to_string().chars().collect::<Vec<_>>()
    } else { format!("\\u{{{:x}}}",character as u32).chars().collect() }).collect()
}
fn lines(selection: &DedicatedWindow, pid: u32) -> io::Result<Vec<String>> {
    let identity = [
        "Allow Agent Bridge to inspect and send supported events to this exact window?".to_owned(),
        format!("Executable: {}",literal(selection.executable.to_str().ok_or_else(invalid)?)),
        format!("WM_CLASS: {}",literal(&selection.class_name)),
        format!("Exact title: {}",literal(&selection.title)),
        format!("Local X server: {}   Process: {pid}",selection.desktop_name),
        "The selected window must return to the foreground when this dialog closes.".to_owned(),
        "Capture is limited to its composited pixmap when supported.".to_owned(),
        "Default / any key / close / timeout: DENY. No global input is authorized.".to_owned(),
    ];
    let mut lines = Vec::new();
    for item in identity {
        for part in item.as_bytes().chunks(90) { lines.push(String::from_utf8(part.to_vec()).map_err(|_|invalid())?); }
        lines.push(String::new());
    }
    if lines.len() > 26 { return Err(error("WINDOW_LOCAL_CONSENT_IDENTITY_TOO_LONG")); }
    Ok(lines)
}
fn allow_hit(x: i16, y: i16, width: u16, height: u16) -> bool {
    x >= width as i16 - 260 && x <= width as i16 - 20 && y >= height as i16 - 70 && y <= height as i16 - 20
}
fn physical(event_type: u8, detail: u8) -> bool { event_type & 0x80 == 0 && detail == 1 }

impl Native {
    pub(super) fn consent(&mut self, selection: &DedicatedWindow) -> io::Result<()> {
        let text = lines(selection, self.process.pid)?;
        self.connection.stream().budget(REQUEST_BUDGET)?;
        let screen = self.connection.setup().roots.iter().find(|screen|screen.root == self.root).ok_or_else(invalid)?;
        let (width, height) = (760u16, 620u16);
        if screen.width_in_pixels < width || screen.height_in_pixels < height { return Err(error("WINDOW_LOCAL_CONSENT_SCREEN_TOO_SMALL")); }
        let window = self.connection.generate_id().map_err(unavailable)?;
        let gc = self.connection.generate_id().map_err(unavailable)?;
        let font = self.connection.generate_id().map_err(unavailable)?;
        self.connection.create_window(x11rb::COPY_DEPTH_FROM_PARENT, window, self.root,
            ((screen.width_in_pixels-width)/2) as i16, ((screen.height_in_pixels-height)/2) as i16,
            width, height, 1, WindowClass::INPUT_OUTPUT, 0,
            &CreateWindowAux::new().background_pixel(screen.white_pixel).border_pixel(screen.black_pixel)
                .event_mask(EventMask::EXPOSURE | EventMask::BUTTON_PRESS | EventMask::BUTTON_RELEASE | EventMask::KEY_PRESS | EventMask::STRUCTURE_NOTIFY))
            .map_err(unavailable)?.check().map_err(unavailable)?;
        self.connection.open_font(font,b"fixed").map_err(unavailable)?.check().map_err(unavailable)?;
        self.connection.create_gc(gc, window, &CreateGCAux::new().foreground(screen.black_pixel).background(screen.white_pixel).font(font))
            .map_err(unavailable)?.check().map_err(unavailable)?;
        let dialog = Dialog { connection: &self.connection, window, gc, font };
        self.connection.change_property8(PropMode::REPLACE, window, AtomEnum::WM_NAME, AtomEnum::STRING, b"Agent Bridge - local exact-window consent")
            .map_err(unavailable)?.check().map_err(unavailable)?;
        self.connection.change_property8(PropMode::REPLACE, window, AtomEnum::WM_CLASS, AtomEnum::STRING, b"agent-bridge\0AgentBridgeConsent\0")
            .map_err(unavailable)?.check().map_err(unavailable)?;
        self.connection.map_window(window).map_err(unavailable)?.check().map_err(unavailable)?;
        self.connection.flush().map_err(unavailable)?;
        let paint = || -> io::Result<()> {
            for (index, line) in text.iter().enumerate() {
                if !line.is_empty() { self.connection.image_text8(window, gc, 20, 26 + (index as i16)*18, line.as_bytes()).map_err(unavailable)?; }
            }
            self.connection.poly_rectangle(window, gc, &[
                Rectangle{x:20,y:height as i16-70,width:220,height:50},
                Rectangle{x:width as i16-260,y:height as i16-70,width:240,height:50},
            ]).map_err(unavailable)?;
            self.connection.image_text8(window,gc,40,height as i16-40,b"DENY (default)").map_err(unavailable)?;
            self.connection.image_text8(window,gc,width as i16-240,height as i16-40,b"ALLOW EXACT WINDOW").map_err(unavailable)?;
            self.connection.flush().map_err(unavailable)
        };
        paint()?;
        let deadline = Instant::now()+Duration::from_secs(60);
        let mut pressed = false;
        let accepted = loop {
            if Instant::now() >= deadline { break false; }
            self.connection.stream().budget(REQUEST_BUDGET)?;
            match self.connection.poll_for_event().map_err(unavailable)? {
                Some(Event::Expose(event)) if event.window == window => paint()?,
                Some(Event::ButtonPress(event)) if event.event == window && physical(event.response_type,event.detail) => {
                    pressed = allow_hit(event.event_x,event.event_y,width,height);
                    if !pressed { break false; }
                }
                Some(Event::ButtonRelease(event)) if event.event == window && physical(event.response_type,event.detail) => {
                    break pressed && allow_hit(event.event_x,event.event_y,width,height);
                }
                Some(Event::KeyPress(event)) if event.event == window && event.response_type & 0x80 == 0 => break false,
                Some(Event::DestroyNotify(event)) if event.window == window => break false,
                Some(Event::ClientMessage(event)) if event.window == window => break false,
                Some(Event::DestroyNotify(event)) if self.watched.contains(&event.window) => { self.revoked.set(true); break false; }
                Some(Event::ReparentNotify(event)) if self.watched.contains(&event.window) => { self.revoked.set(true); break false; }
                Some(_) => {},
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        drop(dialog);
        if !accepted { return Err(error("WINDOW_LOCAL_CONSENT_DENIED")); }
        // Let the window manager restore focus naturally. Never activate or
        // retarget another application on the user's behalf.
        let deadline = Instant::now()+Duration::from_secs(2);
        loop {
            match self.inspect() {
                Ok(_) => return Ok(()),
                Err(issue) if issue.to_string() == "WINDOW_FOREGROUND_REQUIRED" && Instant::now() < deadline => std::thread::sleep(Duration::from_millis(40)),
                Err(issue) => return Err(issue),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consent_never_accepts_synthetic_events_and_renders_identity_literally() {
        assert!(!physical(BUTTON_PRESS_EVENT|0x80,1));
        assert!(!physical(BUTTON_RELEASE_EVENT|0x80,1));
        assert!(!physical(BUTTON_PRESS_EVENT,3));
        assert!(physical(BUTTON_PRESS_EVENT,1));
        assert!(!allow_hit(40,580,760,620));
        assert!(allow_hit(600,580,760,620));
        assert_eq!(literal("a\nβ"),r"a\u{a}\u{3b2}");
    }
}
