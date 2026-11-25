//! Local X11 only: server-attested process ownership, one exact window, no
//! XTest/global input and no root/screen capture. XSendEvent reports dispatch.
use super::*;
use std::cell::Cell;
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use x11rb::connection::Connection;
use x11rb::protocol::{composite::ConnectionExt as _, res::{ClientIdMask, ClientIdSpec, ConnectionExt as _}, xproto::*, Event};
use x11rb::rust_connection::{DefaultStream, PollMode, RustConnection, Stream};
use x11rb::utils::RawFdContainer;
use x11rb::wrapper::ConnectionExt as _;

const REQUEST_BUDGET: Duration = Duration::from_secs(2);
const GRAB_BUDGET: Duration = Duration::from_millis(750);
const MAX_NODES: usize = 256;
fn unavailable<E>(_: E) -> io::Error { error("WINDOW_X11_UNAVAILABLE") }

/// A broken or stalled X server permanently revokes this connection. Closing
/// its socket also releases a server grab if the server stalled mid-operation.
struct BoundedStream { inner: DefaultStream, deadline: Mutex<Instant>, dead: Arc<AtomicBool> }
impl BoundedStream {
    fn budget(&self, duration: Duration) -> io::Result<()> {
        if self.dead.load(Ordering::SeqCst) { return Err(error("WINDOW_X11_CONNECTION_REVOKED")); }
        *self.deadline.lock().map_err(|_|unavailable(()))? = Instant::now() + duration;
        Ok(())
    }
    fn remaining(&self) -> io::Result<Duration> {
        let deadline = *self.deadline.lock().map_err(|_|unavailable(()))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if self.dead.load(Ordering::SeqCst) || remaining.is_zero() {
            self.dead.store(true, Ordering::SeqCst);
            unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_RDWR); }
            Err(error("WINDOW_X11_TIMEOUT"))
        } else { Ok(remaining) }
    }
}
impl Stream for BoundedStream {
    fn poll(&self, mode: PollMode) -> io::Result<()> {
        loop {
            let remaining = self.remaining()?;
            let mut descriptor = libc::pollfd { fd: self.inner.as_raw_fd(), events: 0, revents: 0 };
            if mode.readable() { descriptor.events |= libc::POLLIN; }
            if mode.writable() { descriptor.events |= libc::POLLOUT; }
            let status = unsafe { libc::poll(&mut descriptor, 1, remaining.as_millis().max(1).min(2000) as i32) };
            if status > 0 { return Ok(()); }
            if status == 0 { continue; }
            let issue = io::Error::last_os_error();
            if issue.kind() != io::ErrorKind::Interrupted { return Err(issue); }
        }
    }
    fn read(&self, bytes: &mut [u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        self.remaining()?;
        self.inner.read(bytes, fds)
    }
    fn write(&self, bytes: &[u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        self.remaining()?;
        self.inner.write(bytes, fds)
    }
}
type XConnection = RustConnection<BoundedStream>;

#[derive(Debug, PartialEq, Eq)]
struct Display { number: u16, screen: usize }
fn display(value: &str) -> io::Result<Display> {
    let value = value.strip_prefix("x11:").ok_or_else(||error("WINDOW_PLATFORM_SELECTION_MISMATCH: use x11:0"))?;
    let mut parts = value.split('.');
    let number = parts.next().ok_or_else(invalid)?;
    let screen = parts.next().unwrap_or("0");
    if parts.next().is_some() || number.is_empty() || screen.is_empty()
        || number.len() > 5 || screen.len() > 2
        || !number.bytes().all(|b|b.is_ascii_digit()) || !screen.bytes().all(|b|b.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
        || (screen.len() > 1 && screen.starts_with('0')) { return Err(invalid()); }
    Ok(Display { number: number.parse().map_err(|_|invalid())?, screen: screen.parse().map_err(|_|invalid())? })
}
fn session_display(selection: &DedicatedWindow) -> io::Result<Display> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some_and(|value|!value.is_empty())
        || std::env::var("XDG_SESSION_TYPE").ok().is_some_and(|value|value.eq_ignore_ascii_case("wayland")) {
        return Err(error("WINDOW_WAYLAND_UNSUPPORTED: use a locally consented native X11 session"));
    }
    let wanted = display(&selection.desktop_name)?;
    let current = std::env::var("DISPLAY").map_err(|_|error("WINDOW_GRAPHICAL_SESSION_REQUIRED"))?;
    let current = current.strip_prefix(':').ok_or_else(||error("WINDOW_LOCAL_X11_REQUIRED"))?;
    if display(&format!("x11:{current}"))? != wanted { return Err(error("WINDOW_DISPLAY_MISMATCH")); }
    Ok(wanted)
}
fn local_stream(number: u16) -> io::Result<UnixStream> {
    let path = format!("/tmp/.X11-unix/X{number}");
    let metadata = fs::symlink_metadata(&path).map_err(|_|error("WINDOW_GRAPHICAL_SESSION_REQUIRED"))?;
    if !metadata.file_type().is_socket() || ![0, unsafe { libc::getuid() }].contains(&metadata.uid()) {
        return Err(error("WINDOW_LOCAL_X11_REQUIRED"));
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 { return Err(unavailable(())); }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as _;
    for (slot, byte) in address.sun_path.iter_mut().zip(path.bytes()) { *slot = byte as _; }
    let length = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    let status = unsafe { libc::connect(fd, (&address as *const libc::sockaddr_un).cast(), length) };
    if status != 0 {
        let issue = io::Error::last_os_error();
        if !matches!(issue.raw_os_error(), Some(libc::EINPROGRESS) | Some(libc::EAGAIN)) { return Err(unavailable(issue)); }
        let mut poll = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        if unsafe { libc::poll(&mut poll, 1, 1000) } <= 0 { return Err(error("WINDOW_X11_TIMEOUT")); }
        let mut code = 0i32; let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, (&mut code as *mut i32).cast(), &mut size) } != 0 || code != 0 {
            return Err(unavailable(()));
        }
    }
    Ok(stream)
}
fn connect(display: &Display) -> io::Result<XConnection> {
    let (stream, (family, address)) = DefaultStream::from_unix_stream(local_stream(display.number)?).map_err(unavailable)?;
    let auth = authority(family, &address, display.number)?;
    RustConnection::connect_to_stream_with_auth_info(BoundedStream {
        inner: stream, deadline: Mutex::new(Instant::now() + REQUEST_BUDGET), dead: Arc::new(AtomicBool::new(false)),
    }, display.screen, auth.0, auth.1).map_err(unavailable)
}
fn authority(family: x11rb::reexports::x11rb_protocol::xauth::Family, address: &[u8], number: u16) -> io::Result<(Vec<u8>,Vec<u8>)> {
    use x11rb::reexports::x11rb_protocol::xauth::Family;
    // Read one bounded regular-file handle. O_NONBLOCK prevents an authority
    // path replaced by a FIFO from hanging startup. Never log cookie bytes.
    let auth_path = std::env::var_os("XAUTHORITY").map(PathBuf::from).or_else(||
        std::env::var_os("HOME").map(|home|PathBuf::from(home).join(".Xauthority")));
    let Some(path) = auth_path else { return Ok((Vec::new(),Vec::new())); };
    let file = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK|libc::O_CLOEXEC).open(path) {
        Ok(file) => file,
        Err(issue) if issue.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(),Vec::new())),
        Err(_) => return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE")),
    };
    let metadata=file.metadata().map_err(|_|error("WINDOW_X11_AUTHORITY_UNAVAILABLE"))?;
    if !metadata.is_file() || metadata.len()>1024*1024 { return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE")); }
    let mut bytes=Vec::new();
    file.take(1024*1024+1).read_to_end(&mut bytes).map_err(|_|error("WINDOW_X11_AUTHORITY_UNAVAILABLE"))?;
    if bytes.len()>1024*1024 { return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE")); }
    fn word(input:&mut &[u8])->io::Result<u16>{
        if input.len()<2{return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE"));}
        let value=u16::from_be_bytes([input[0],input[1]]);*input=&input[2..];Ok(value)
    }
    fn field<'a>(input:&mut &'a [u8])->io::Result<&'a [u8]>{
        let length=usize::from(word(input)?);
        if input.len()<length{return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE"));}
        let (value,remaining)=input.split_at(length);*input=remaining;Ok(value)
    }
    let mut input=bytes.as_slice();let display=number.to_string();let mut count=0;
    while !input.is_empty(){
        count+=1;if count>4096{return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE"));}
        let candidate=Family::from(word(&mut input)?);
        let host=field(&mut input)?;let screen=field(&mut input)?;
        let name=field(&mut input)?;let secret=field(&mut input)?;
        if (candidate==Family::WILD || (candidate==family&&host==address))
            &&(screen.is_empty()||screen==display.as_bytes())&&name==b"MIT-MAGIC-COOKIE-1" {
            if secret.len()!=16{return Err(error("WINDOW_X11_AUTHORITY_UNAVAILABLE"));}
            return Ok((name.to_vec(),secret.to_vec()));
        }
    }
    Ok((Vec::new(),Vec::new()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity { pid: u32, started: u64, device: u64, inode: u64, size: u64, modified: (i64,i64) }
fn start_time(stat: &str) -> io::Result<u64> {
    // comm is parenthesized and may itself contain spaces or parentheses.
    let (_, rest) = stat.rsplit_once(')').ok_or_else(||error("WINDOW_PROCESS_UNAVAILABLE"))?;
    rest.split_whitespace().nth(19).and_then(|value|value.parse().ok()).ok_or_else(||error("WINDOW_PROCESS_UNAVAILABLE"))
}
fn read_limited(path: impl AsRef<std::path::Path>, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path).map_err(|_|error("WINDOW_PROCESS_UNAVAILABLE"))?.take((limit + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_|error("WINDOW_PROCESS_UNAVAILABLE"))?;
    if bytes.len() > limit { return Err(error("WINDOW_PROCESS_UNAVAILABLE")); }
    Ok(bytes)
}
fn process_identity(pid: u32, selection: &DedicatedWindow) -> io::Result<ProcessIdentity> {
    process_identity_with_path_check(pid,selection,true)
}
fn process_identity_with_path_check(pid: u32, selection: &DedicatedWindow, check_selected_path: bool) -> io::Result<ProcessIdentity> {
    if pid == 0 { return Err(error("WINDOW_PROCESS_UNAVAILABLE")); }
    let directory = PathBuf::from(format!("/proc/{pid}"));
    let stat = read_limited(directory.join("stat"), 8192)?;
    let started = start_time(std::str::from_utf8(&stat).map_err(|_|invalid())?)?;
    let status = read_limited(directory.join("status"), 65536)?;
    let status = std::str::from_utf8(&status).map_err(|_|invalid())?;
    let uid = unsafe { libc::getuid() };
    let uids = status.lines().find_map(|line|line.strip_prefix("Uid:")).ok_or_else(||error("WINDOW_PROCESS_OWNER_MISMATCH"))?
        .split_whitespace().map(str::parse::<u32>).collect::<Result<Vec<_>, _>>().map_err(|_|invalid())?;
    if uids.len() != 4 || uids.iter().any(|value|*value != uid) { return Err(error("WINDOW_PROCESS_OWNER_MISMATCH")); }
    let path = fs::read_link(directory.join("exe")).map_err(|_|error("WINDOW_PROCESS_UNAVAILABLE"))?;
    if path != selection.executable || (check_selected_path && fs::canonicalize(&selection.executable).ok().as_ref() != Some(&selection.executable)) {
        return Err(error("WINDOW_EXECUTABLE_MISMATCH"));
    }
    let actual = fs::metadata(directory.join("exe")).map_err(|_|error("WINDOW_PROCESS_UNAVAILABLE"))?;
    if !actual.is_file() { return Err(error("WINDOW_PROCESS_CHANGED")); }
    if check_selected_path {
        let expected = fs::metadata(&selection.executable).map_err(|_|error("WINDOW_PROCESS_UNAVAILABLE"))?;
        if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) { return Err(error("WINDOW_PROCESS_CHANGED")); }
    }
    let after = read_limited(directory.join("stat"), 8192)?;
    if start_time(std::str::from_utf8(&after).map_err(|_|invalid())?)? != started { return Err(error("WINDOW_PROCESS_CHANGED")); }
    Ok(ProcessIdentity { pid, started, device: actual.dev(), inode: actual.ino(), size: actual.len(), modified: (actual.mtime(), actual.mtime_nsec()) })
}
fn atom(connection: &XConnection, name: &[u8]) -> io::Result<Atom> {
    Ok(connection.intern_atom(false, name).map_err(unavailable)?.reply().map_err(unavailable)?.atom)
}
struct Atoms { name: Atom, utf8: Atom }
fn property(connection: &XConnection, window: Window, name: Atom, expected: Atom) -> io::Result<Option<Vec<u8>>> {
    let reply = connection.get_property(false, window, name, expected, 0, 257).map_err(unavailable)?.reply().map_err(unavailable)?;
    if reply.type_ == 0 { return Ok(None); }
    if reply.type_ != expected || reply.format != 8 || reply.bytes_after != 0 || reply.value.len() > 1024 {
        return Err(error("WINDOW_X11_PROPERTY_UNAVAILABLE"));
    }
    Ok(Some(reply.value))
}
fn title(connection: &XConnection, atoms: &Atoms, window: Window) -> io::Result<String> {
    let bytes = match property(connection, window, atoms.name, atoms.utf8)? {
        Some(bytes) => bytes,
        None => property(connection, window, AtomEnum::WM_NAME.into(), AtomEnum::STRING.into())?.unwrap_or_default(),
    };
    let value = String::from_utf8(bytes).map_err(|_|error("WINDOW_X11_PROPERTY_UNAVAILABLE"))?;
    if value.chars().any(char::is_control) { return Err(error("WINDOW_X11_PROPERTY_UNAVAILABLE")); }
    Ok(value)
}
fn class(connection: &XConnection, window: Window) -> io::Result<String> {
    let bytes = property(connection, window, AtomEnum::WM_CLASS.into(), AtomEnum::STRING.into())?.unwrap_or_default();
    if bytes.is_empty() { return Ok(String::new()); }
    let mut fields = bytes.split(|byte|*byte == 0);
    let _instance = fields.next().ok_or_else(invalid)?;
    let class = fields.next().ok_or_else(invalid)?;
    if fields.next() != Some(&[][..]) || fields.next().is_some() { return Err(error("WINDOW_X11_PROPERTY_UNAVAILABLE")); }
    let value = std::str::from_utf8(class).map_err(|_|invalid())?;
    if value.is_empty() || value.chars().any(char::is_control) { return Err(invalid()); }
    Ok(value.into())
}
fn owner(connection: &XConnection, window: Window) -> io::Result<u32> {
    // _NET_WM_PID is client-controlled and is deliberately never consulted.
    let specs = [ClientIdSpec { client: window, mask: ClientIdMask::LOCAL_CLIENT_PID }];
    let reply = connection.res_query_client_ids(&specs).map_err(unavailable)?.reply().map_err(unavailable)?;
    if reply.ids.len() != 1 || reply.ids[0].spec.mask != ClientIdMask::LOCAL_CLIENT_PID || reply.ids[0].value.len() != 1 {
        return Err(error("WINDOW_XRES_LOCAL_PROCESS_REQUIRED"));
    }
    let pid = reply.ids[0].value[0];
    if pid == 0 { Err(error("WINDOW_XRES_LOCAL_PROCESS_REQUIRED")) } else { Ok(pid) }
}
fn parent(connection: &XConnection, window: Window) -> io::Result<Window> {
    Ok(connection.query_tree(window).map_err(unavailable)?.reply().map_err(unavailable)?.parent)
}
#[derive(Clone)]
struct Control { window: Window, parent: Window, width: u16, height: u16, x: i16, y: i16, title: String, class: String }
struct ServerGrab<'a> {
    connection: &'a XConnection,
    finished: Option<std::sync::mpsc::Sender<()>>,
    watchdog: Option<std::thread::JoinHandle<()>>,
}
impl Drop for ServerGrab<'_> {
    fn drop(&mut self) {
        // A flush alone does not prove that the server processed UngrabServer.
        // Cancel the independent watchdog only after the checked round trip.
        let released=self.connection.ungrab_server().map_err(unavailable)
            .and_then(|cookie|cookie.check().map_err(unavailable)).is_ok();
        if released { if let Some(done)=self.finished.take(){let _=done.send(());} }
        drop(self.finished.take()); // an abandoned release revokes immediately
        if let Some(watchdog)=self.watchdog.take(){let _=watchdog.join();}
    }
}
fn grab(connection: &XConnection) -> io::Result<ServerGrab<'_>> {
    let deadline=Instant::now()+GRAB_BUDGET;
    connection.stream().budget(GRAB_BUDGET)?;
    // A deadline checked only during X I/O cannot bound a filesystem stall or
    // CPU work while the server is grabbed. This thread owns a duplicate of
    // this exact socket (no borrowed/reusable FD number) and can revoke it
    // independently even while the calling thread is blocked elsewhere.
    let descriptor=unsafe{libc::fcntl(connection.stream().inner.as_raw_fd(),libc::F_DUPFD_CLOEXEC,3)};
    if descriptor<0{return Err(error("WINDOW_X11_WATCHDOG_UNAVAILABLE"));}
    let socket=unsafe{UnixStream::from_raw_fd(descriptor)};
    let dead=Arc::clone(&connection.stream().dead);
    let (finished,completion)=std::sync::mpsc::channel();
    let watchdog=std::thread::Builder::new().name("agent-bridge-x11-grab".into()).spawn(move||{
        if completion.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_err(){
            dead.store(true,Ordering::SeqCst);
            let _=socket.shutdown(std::net::Shutdown::Both);
        }
    }).map_err(|_|error("WINDOW_X11_WATCHDOG_UNAVAILABLE"))?;
    let guard=ServerGrab{connection,finished:Some(finished),watchdog:Some(watchdog)};
    connection.grab_server().map_err(unavailable)?.check().map_err(unavailable)?;
    Ok(guard)
}

struct CapturedPixels { data:Vec<u8>, width:usize, height:usize, stride:usize, bytes_per_pixel:usize, lsb:bool }
impl CapturedPixels {
    fn rgb(self)->(Vec<u8>,usize,usize){
        let mut rgb=Vec::with_capacity(self.width*self.height*3);
        for row in self.data.chunks_exact(self.stride){
            for pixel in row[..self.width*self.bytes_per_pixel].chunks_exact(self.bytes_per_pixel){
                if self.lsb{rgb.extend_from_slice(&[pixel[2],pixel[1],pixel[0]]);}
                else{let shift=self.bytes_per_pixel-3;rgb.extend_from_slice(&pixel[shift..shift+3]);}
            }
        }
        (rgb,self.width,self.height)
    }
}

pub(super) struct Native {
    selection: DedicatedWindow, connection: XConnection, root: Window, window: Window,
    process: ProcessIdentity, atoms: Atoms, watched: HashSet<Window>, revoked: Cell<bool>,
    controls: Vec<Control>, composite: bool,
}
impl Native {
    pub(super) fn connect(selection: &DedicatedWindow) -> io::Result<Self> {
        selection.validate()?;
        let display = session_display(selection)?;
        Self::connect_display(selection, &display)
    }
    fn connect_display(selection: &DedicatedWindow, display: &Display) -> io::Result<Self> {
        let connection = connect(display)?;
        Self::from_connection(selection, connection, display.screen)
    }
    fn from_connection(selection: &DedicatedWindow, connection: XConnection, screen: usize) -> io::Result<Self> {
        let version = connection.res_query_version(1, 2).map_err(unavailable)?.reply().map_err(unavailable)?;
        if (version.server_major, version.server_minor) < (1, 2) { return Err(error("WINDOW_XRES_1_2_REQUIRED")); }
        let composite = connection.composite_query_version(0, 4).ok().and_then(|cookie|cookie.reply().ok())
            .is_some_and(|reply|(reply.major_version, reply.minor_version) >= (0, 2));
        let root = connection.setup().roots.get(screen).ok_or_else(invalid)?.root;
        let atoms = Atoms { name: atom(&connection, b"_NET_WM_NAME")?, utf8: atom(&connection, b"UTF8_STRING")? };
        let mut window = connection.get_input_focus().map_err(unavailable)?.reply().map_err(unavailable)?.focus;
        let mut matched = false;
        for _ in 0..32 {
            if window <= 1 || window == root { break; }
            if class(&connection, window)? == selection.class_name && title(&connection, &atoms, window)? == selection.title { matched = true; break; }
            window = parent(&connection, window)?;
        }
        if !matched { return Err(error("WINDOW_SELECTION_MISMATCH")); }
        let process = process_identity(owner(&connection, window)?, selection)?;
        connection.change_window_attributes(window, &ChangeWindowAttributesAux::new().event_mask(EventMask::STRUCTURE_NOTIFY))
            .map_err(unavailable)?.check().map_err(unavailable)?;
        let mut native = Self { selection: selection.clone(), connection, root, window, process, atoms,
            watched: HashSet::from([window]), revoked: Cell::new(false), controls: Vec::new(), composite };
        native.inspect()?;
        Ok(native)
    }
    fn drain(&self) -> io::Result<()> {
        let mut count = 0;
        while let Some(event) = self.connection.poll_for_event().map_err(unavailable)? {
            count += 1;
            if count > 1024 { self.revoked.set(true); break; }
            let changed = match event { Event::DestroyNotify(event) => Some(event.window), Event::ReparentNotify(event) => Some(event.window), _ => None };
            if changed.is_some_and(|window|self.watched.contains(&window)) { self.revoked.set(true); }
        }
        if self.revoked.get() { Err(error("WINDOW_IDENTITY_CHANGED")) } else { Ok(()) }
    }
    fn verify_x(&self, check_selected_path: bool) -> io::Result<NativeWindow> {
        if self.revoked.get() || owner(&self.connection, self.window)? != self.process.pid
            || process_identity_with_path_check(self.process.pid, &self.selection,check_selected_path)? != self.process
            || class(&self.connection, self.window)? != self.selection.class_name
            || title(&self.connection, &self.atoms, self.window)? != self.selection.title { return Err(error("WINDOW_IDENTITY_CHANGED")); }
        let attributes = self.connection.get_window_attributes(self.window).map_err(unavailable)?.reply().map_err(unavailable)?;
        if attributes.class != WindowClass::INPUT_OUTPUT || attributes.map_state != MapState::VIEWABLE || attributes.override_redirect {
            return Err(error("WINDOW_VISIBLE_APPLICATION_REQUIRED"));
        }
        let mut focused = self.connection.get_input_focus().map_err(unavailable)?.reply().map_err(unavailable)?.focus;
        let mut matched = false;
        for _ in 0..32 {
            if focused == self.window { matched = true; break; }
            if focused <= 1 || focused == self.root || owner(&self.connection, focused)? != self.process.pid { break; }
            focused = parent(&self.connection, focused)?;
        }
        if !matched { return Err(error("WINDOW_FOREGROUND_REQUIRED")); }
        let geometry = self.connection.get_geometry(self.window).map_err(unavailable)?.reply().map_err(unavailable)?;
        let position = self.connection.translate_coordinates(self.window, self.root, 0, 0).map_err(unavailable)?.reply().map_err(unavailable)?;
        if geometry.width == 0 || geometry.height == 0 || geometry.width > 4096 || geometry.height > 4096 || !position.same_screen {
            return Err(error("WINDOW_GEOMETRY_UNSUPPORTED"));
        }
        Ok(NativeWindow { identity: format!("x11:{}:{}:{}", self.window, self.process.pid, self.process.started),
            x: position.dst_x.into(), y: position.dst_y.into(), width: geometry.width.into(), height: geometry.height.into(), enabled: true })
    }
    fn control(&self, window: Window) -> io::Result<Control> {
        if owner(&self.connection, window)? != self.process.pid { return Err(error("WINDOW_FOREIGN_CHILD_REFUSED")); }
        let attributes = self.connection.get_window_attributes(window).map_err(unavailable)?.reply().map_err(unavailable)?;
        if attributes.class != WindowClass::INPUT_OUTPUT || attributes.map_state != MapState::VIEWABLE { return Err(error("WINDOW_CONTROL_UNAVAILABLE")); }
        let geometry = self.connection.get_geometry(window).map_err(unavailable)?.reply().map_err(unavailable)?;
        if geometry.width == 0 || geometry.height == 0 { return Err(error("WINDOW_CONTROL_UNAVAILABLE")); }
        Ok(Control { window, parent: parent(&self.connection, window)?, width: geometry.width, height: geometry.height,
            x: geometry.x, y: geometry.y, title: title(&self.connection, &self.atoms, window)?, class: class(&self.connection, window)? })
    }
    fn walk(&self) -> io::Result<Vec<Control>> {
        let mut queue = VecDeque::from([(self.window, 0usize)]);
        let mut seen = HashSet::new(); let mut controls = Vec::new();
        while let Some((window, depth)) = queue.pop_front() {
            if !seen.insert(window) || seen.len() > MAX_NODES || depth > 12 { return Err(error("WINDOW_TREE_LIMIT")); }
            // All descendants must have the same server-attested owner, even
            // invisible children: an embedded foreign drawable is never read.
            if owner(&self.connection, window)? != self.process.pid { return Err(error("WINDOW_FOREIGN_CHILD_REFUSED")); }
            let attributes = self.connection.get_window_attributes(window).map_err(unavailable)?.reply().map_err(unavailable)?;
            if attributes.class == WindowClass::INPUT_OUTPUT && attributes.map_state == MapState::VIEWABLE { controls.push(self.control(window)?); }
            let tree = self.connection.query_tree(window).map_err(unavailable)?.reply().map_err(unavailable)?;
            if tree.children.len() + queue.len() + seen.len() > MAX_NODES { return Err(error("WINDOW_TREE_LIMIT")); }
            queue.extend(tree.children.into_iter().map(|child|(child, depth + 1)));
        }
        Ok(controls)
    }
    fn capture(&self) -> io::Result<CapturedPixels> {
        if !self.composite { return Err(error("WINDOW_XCOMPOSITE_UNAVAILABLE")); }
        let geometry = self.connection.get_geometry(self.window).map_err(unavailable)?.reply().map_err(unavailable)?;
        if geometry.width > 4096 || geometry.height > 4096 { return Err(error("WINDOW_CAPTURE_LIMIT")); }
        let attributes = self.connection.get_window_attributes(self.window).map_err(unavailable)?.reply().map_err(unavailable)?;
        let visual = self.connection.setup().roots.iter().flat_map(|root|root.allowed_depths.iter())
            .flat_map(|depth|depth.visuals.iter()).find(|visual|visual.visual_id == attributes.visual)
            .ok_or_else(||error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED"))?;
        if visual.class != VisualClass::TRUE_COLOR { return Err(error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED")); }
        let format = self.connection.setup().pixmap_formats.iter().find(|format|format.depth == geometry.depth)
            .ok_or_else(||error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED"))?;
        if ![24,32].contains(&format.bits_per_pixel) || ![8,16,32].contains(&format.scanline_pad)
            || visual.red_mask != 0xff0000 || visual.green_mask != 0x00ff00 || visual.blue_mask != 0x0000ff {
            return Err(error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED"));
        }
        let pixmap = self.connection.generate_id().map_err(unavailable)?;
        // Naming succeeds only for an already redirected window. We do not
        // redirect/repaint user windows or fall back to GetImage(window/root).
        self.connection.composite_name_window_pixmap(self.window, pixmap).map_err(unavailable)?.check()
            .map_err(|_|error("WINDOW_CAPTURE_REQUIRES_COMPOSITED_WINDOW"))?;
        let captured = (|| {
            let backing = self.connection.get_geometry(pixmap).map_err(unavailable)?.reply().map_err(unavailable)?;
            let border = geometry.border_width;
            if backing.depth != geometry.depth || backing.width != geometry.width.saturating_add(border.saturating_mul(2))
                || backing.height != geometry.height.saturating_add(border.saturating_mul(2)) || border > i16::MAX as u16 {
                return Err(error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED"));
            }
            self.connection.get_image(ImageFormat::Z_PIXMAP, pixmap, border as i16, border as i16, geometry.width, geometry.height, u32::MAX)
                .map_err(unavailable)?.reply().map_err(unavailable)
        })();
        let _ = self.connection.free_pixmap(pixmap);
        let captured = captured?;
        let bytes_per_pixel = usize::from(format.bits_per_pixel) / 8;
        let width = usize::from(geometry.width); let height = usize::from(geometry.height);
        let stride = (width * usize::from(format.bits_per_pixel)).div_ceil(usize::from(format.scanline_pad)) * usize::from(format.scanline_pad) / 8;
        if captured.depth != geometry.depth || captured.data.len() != stride * height { return Err(error("WINDOW_CAPTURE_FORMAT_UNSUPPORTED")); }
        let lsb = self.connection.setup().image_byte_order == ImageOrder::LSB_FIRST;
        Ok(CapturedPixels{data:captured.data,width,height,stride,bytes_per_pixel,lsb})
    }
    fn keycode(&self, key: &str) -> io::Result<u8> {
        let symbol: u32 = match key { "Enter"=>0xff0d, "Escape"=>0xff1b, "Tab"=>0xff09, "ArrowLeft"=>0xff51,
            "ArrowUp"=>0xff52, "ArrowRight"=>0xff53, "ArrowDown"=>0xff54, _=>return Err(unsupported()) };
        let setup = self.connection.setup();
        let count = setup.max_keycode.checked_sub(setup.min_keycode).and_then(|value|value.checked_add(1)).ok_or_else(unsupported)?;
        let mapping = self.connection.get_keyboard_mapping(setup.min_keycode, count).map_err(unavailable)?.reply().map_err(unavailable)?;
        if mapping.keysyms_per_keycode == 0 { return Err(unsupported()); }
        mapping.keysyms.chunks(usize::from(mapping.keysyms_per_keycode)).position(|symbols|symbols.first() == Some(&symbol))
            .and_then(|index|setup.min_keycode.checked_add(index as u8)).ok_or_else(unsupported)
    }
}

impl Backend for Native {
    fn inspect(&mut self) -> io::Result<NativeWindow> {
        self.connection.stream().budget(REQUEST_BUDGET)?;
        let current = self.verify_x(true)?;
        self.drain()?;
        Ok(current)
    }
    fn confirm(&mut self, selection: &DedicatedWindow) -> io::Result<()> { self.consent(selection) }
    fn capabilities(&self) -> Capabilities {
        Capabilities { backend: "x11_scoped_events", tree: "x11_window_tree_not_accessibility", actions: &["wait","click","send_keys"], screenshot: self.composite }
    }
    fn snapshot(&mut self, options: SnapshotOptions) -> io::Result<NativeSnapshot> {
        self.inspect()?; self.controls.clear();
        let (controls, pixels) = {
            let _guard = grab(&self.connection)?;
            // Full pathname qualification ran immediately before the grab.
            // Keep only the live /proc incarnation checks inside it; even a
            // stalled procfs handle is covered by the independent watchdog.
            self.verify_x(false)?;
            self.drain()?;
            let controls = self.walk()?;
            for control in &controls {
                if self.watched.len() >= 1024 && !self.watched.contains(&control.window) { return Err(error("WINDOW_OBSERVATION_LIMIT_RESELECT_REQUIRED")); }
                self.connection.change_window_attributes(control.window, &ChangeWindowAttributesAux::new().event_mask(EventMask::STRUCTURE_NOTIFY))
                    .map_err(unavailable)?.check().map_err(unavailable)?;
                self.watched.insert(control.window);
            }
            let pixels = if options.screenshot { Some(self.capture()) } else { None };
            self.verify_x(false)?;
            (controls, pixels)
        };
        self.connection.stream().budget(REQUEST_BUDGET)?;
        self.inspect()?;
        let mut truncated = controls.len() > options.maximum;
        self.controls = controls.into_iter().take(options.maximum).collect();
        let mut elements = if options.tree { self.controls.iter().enumerate().map(|(index, control)|json!({
            "ref":format!("control:{}",index+1),"role":"x11_window","name":control.title,"class_name":control.class,
            "x":control.x,"y":control.y,"width":control.width,"height":control.height,
            "supports_click":true,"supports_send_keys":true,"synthetic_events_may_be_ignored":true,
        })).collect() } else { Vec::new() };
        if !options.tree { self.controls.clear(); }
        let (screenshot, screenshot_status) = match pixels {
            Some(Ok(captured)) => {
                // Conversion and encoding happen after UngrabServer. They are
                // bounded by the validated pixel dimensions, not a UI freeze.
                if options.tree {
                    image::bound_screenshot_tree(&mut elements);
                    truncated |= elements.len() < self.controls.len();
                    self.controls.truncate(elements.len());
                }
                let(rgb,width,height)=captured.rgb();
                (Some(image::png(width,height,&rgb)?),"captured_selected_window_pixmap")
            },
            Some(Err(issue)) => match issue.to_string().as_str() {
                "WINDOW_XCOMPOSITE_UNAVAILABLE" => (None,"unsupported_xcomposite_missing"),
                "WINDOW_CAPTURE_REQUIRES_COMPOSITED_WINDOW" => (None,"unsupported_window_not_composited"),
                "WINDOW_CAPTURE_FORMAT_UNSUPPORTED" => (None,"unsupported_native_pixel_format"),
                _ => return Err(issue),
            },
            None => (None,"not_requested"),
        };
        Ok(NativeSnapshot { elements, truncated, screenshot, screenshot_status })
    }
    fn action(&mut self, action: &Action) -> io::Result<Value> {
        self.inspect()?;
        let selector = match action { Action::Click { selector } | Action::SendKeys { selector,.. } => selector, _=>return Err(unsupported()) };
        let index = selector.strip_prefix("control:").and_then(|value|value.parse::<usize>().ok()).and_then(|value|value.checked_sub(1))
            .filter(|index|selector == &format!("control:{}",index+1)).ok_or_else(invalid)?;
        let observed = self.controls.get(index).cloned().ok_or_else(||error("WINDOW_CONTROL_STALE"))?;
        self.controls.clear();
        let _guard = grab(&self.connection)?;
        self.verify_x(false)?;
        self.drain()?;
        let current = self.walk()?.into_iter().find(|control|control.window == observed.window).ok_or_else(||error("WINDOW_CONTROL_STALE"))?;
        if current.parent != observed.parent || current.width != observed.width || current.height != observed.height
            || current.x != observed.x || current.y != observed.y || current.title != observed.title || current.class != observed.class {
            return Err(error("WINDOW_CONTROL_STALE"));
        }
        let position = self.connection.translate_coordinates(current.window, self.root, (current.width / 2) as i16, (current.height / 2) as i16)
            .map_err(unavailable)?.reply().map_err(unavailable)?;
        if !position.same_screen { return Err(error("WINDOW_CONTROL_STALE")); }
        match action {
            Action::Click {..} => {
                let mut event = ButtonPressEvent { response_type: BUTTON_PRESS_EVENT, detail: 1, sequence: 0, time: x11rb::CURRENT_TIME,
                    root: self.root, event: current.window, child: 0, root_x: position.dst_x, root_y: position.dst_y,
                    event_x: (current.width / 2) as i16, event_y: (current.height / 2) as i16, state: 0u16.into(), same_screen: true };
                self.connection.send_event(false, current.window, EventMask::NO_EVENT, event).map_err(unavailable)?.check()
                    .map_err(|_|error("WINDOW_ACTION_OUTCOME_UNCERTAIN"))?;
                event.response_type = BUTTON_RELEASE_EVENT; event.state = KeyButMask::BUTTON1;
                self.connection.send_event(false, current.window, EventMask::NO_EVENT, event).map_err(unavailable)?.check()
                    .map_err(|_|error("WINDOW_ACTION_OUTCOME_UNCERTAIN"))?;
            }
            Action::SendKeys {keys,..} => {
                let mut event = KeyPressEvent { response_type: KEY_PRESS_EVENT, detail: self.keycode(keys)?, sequence: 0, time: x11rb::CURRENT_TIME,
                    root: self.root, event: current.window, child: 0, root_x: position.dst_x, root_y: position.dst_y,
                    event_x: 0, event_y: 0, state: 0u16.into(), same_screen: true };
                self.connection.send_event(false, current.window, EventMask::NO_EVENT, event).map_err(unavailable)?.check()
                    .map_err(|_|error("WINDOW_ACTION_OUTCOME_UNCERTAIN"))?;
                event.response_type = KEY_RELEASE_EVENT;
                self.connection.send_event(false, current.window, EventMask::NO_EVENT, event).map_err(unavailable)?.check()
                    .map_err(|_|error("WINDOW_ACTION_OUTCOME_UNCERTAIN"))?;
            }
            _ => return Err(unsupported()),
        }
        Ok(json!({"dispatched":true,"effect_verified":false,"transport":"x11_send_event_exact_window","synthetic_events_may_be_ignored":true}))
    }
}

#[path="x11_consent.rs"]
mod consent;
#[cfg(test)]
#[path="x11_tests.rs"]
mod tests;
