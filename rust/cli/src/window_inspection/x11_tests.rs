use super::*;
use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};

#[test]
fn display_and_process_identity_reject_aliases_and_parse_hostile_comm() {
    assert_eq!(display("x11:12.1").unwrap(), Display { number:12,screen:1 });
    for value in ["x11:localhost:0","x11:tcp/host:0","x11:../0","x11:00","x11:0.00","x11:0.0.0","x11:-1","x11:65536"] {
        assert!(display(value).is_err(),"{value}");
    }
    let stat = format!("123 (space ) and (paren) S {} 4242 99",std::iter::repeat_n("0",18).collect::<Vec<_>>().join(" "));
    assert_eq!(start_time(&stat).unwrap(),4242);
    let selection = selected("0");
    let process = process_identity(std::process::id(),&selection).unwrap();
    assert_eq!(process.pid,std::process::id());
    assert!(process.started>0);
    let mut wrong = selection; wrong.executable=PathBuf::from("/not-the-selected-executable");
    assert_eq!(process_identity(std::process::id(),&wrong).unwrap_err().to_string(),"WINDOW_EXECUTABLE_MISMATCH");
}

#[test]
fn stalled_x11_handshake_is_bounded_and_connection_stays_revoked() {
    let (socket,_peer)=UnixStream::pair().unwrap();
    let (inner,_)=DefaultStream::from_unix_stream(socket).unwrap();
    let stream=BoundedStream {inner,deadline:Mutex::new(Instant::now()+Duration::from_millis(35)),dead:Default::default()};
    let start=Instant::now();
    let result=RustConnection::connect_to_stream(stream,0);
    assert!(result.is_err());
    assert!(start.elapsed()<Duration::from_secs(1));
    let (socket,_peer)=UnixStream::pair().unwrap();
    let (inner,_)=DefaultStream::from_unix_stream(socket).unwrap();
    let stream=BoundedStream {inner,deadline:Mutex::new(Instant::now()),dead:Default::default()};
    assert!(stream.remaining().is_err());
    assert!(stream.budget(Duration::from_secs(2)).is_err());
}

struct Server { child: Child, number:String, errors:Option<std::thread::JoinHandle<Vec<u8>>> }
impl Drop for Server {fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();if let Some(errors)=self.errors.take(){let _=errors.join();}}}
impl Server {
    fn start()->Self {
        let child=Command::new("Xvfb").args(["-displayfd","1","-screen","0","1024x768x24","-nolisten","tcp","-ac","-noreset"])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
            .expect("The native X11 regression requires Xvfb (its own isolated display; never the user's DISPLAY)");
        let mut server=Self{child,number:String::new(),errors:None};
        let mut errors=server.child.stderr.take().unwrap();
        server.errors=Some(std::thread::spawn(move||{
            let mut collected=Vec::new();let mut buffer=[0u8;1024];
            loop {match errors.read(&mut buffer){Ok(0)|Err(_)=>break,Ok(count)=>{
                let keep=count.min(4096usize.saturating_sub(collected.len()));collected.extend_from_slice(&buffer[..keep]);
            }}}
            collected
        }));
        let output=server.child.stdout.take().unwrap();
        let (send,receive)=std::sync::mpsc::channel();
        let reader=std::thread::spawn(move||{let mut line=String::new();let result=std::io::BufReader::new(output).read_line(&mut line);let _=send.send((result,line));});
        let received=receive.recv_timeout(Duration::from_secs(5));
        if let Ok((Ok(_),line))=received{server.number=line.trim().into();}
        if server.number.parse::<u16>().is_err(){
            let _=server.child.kill();let _=server.child.wait();let _=reader.join();
            let errors=server.errors.take().unwrap().join().unwrap();
            panic!("isolated Xvfb did not create its socket; use a private writable /tmp mount when WSLg owns it: {}",String::from_utf8_lossy(&errors));
        }
        reader.join().unwrap();
        server
    }
    fn connection(&self)->XConnection { test_connection(self.number.parse().unwrap()) }
}
fn test_connection(number:u16)->XConnection {
    // Dedicated Xvfb -ac connection. Do not read a user's Xauthority file.
    let (inner,_)=DefaultStream::from_unix_stream(local_stream(number).unwrap()).unwrap();
    RustConnection::connect_to_stream(BoundedStream {inner,deadline:Mutex::new(Instant::now()+REQUEST_BUDGET),dead:Default::default()},0).unwrap()
}
fn selected(number:&str)->DedicatedWindow {
    DedicatedWindow {desktop_name:format!("x11:{number}"),executable:fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        class_name:"BridgeFixture".into(),title:"Approved fixture".into()}
}
fn create(connection:&XConnection,parent:Window,id:Window,title:&str,color:u32,composite:bool) {
    connection.stream().budget(REQUEST_BUDGET).unwrap();
    connection.create_window(x11rb::COPY_DEPTH_FROM_PARENT,id,parent,20,20,220,140,0,WindowClass::INPUT_OUTPUT,0,
        &CreateWindowAux::new().background_pixel(color).event_mask(EventMask::BUTTON_PRESS|EventMask::BUTTON_RELEASE|EventMask::KEY_PRESS|EventMask::KEY_RELEASE))
        .unwrap().check().unwrap();
    connection.change_property8(PropMode::REPLACE,id,AtomEnum::WM_CLASS,AtomEnum::STRING,b"fixture\0BridgeFixture\0").unwrap().check().unwrap();
    connection.change_property8(PropMode::REPLACE,id,AtomEnum::WM_NAME,AtomEnum::STRING,title.as_bytes()).unwrap().check().unwrap();
    if composite { connection.composite_redirect_window(id,x11rb::protocol::composite::Redirect::AUTOMATIC).unwrap().check().unwrap(); }
    connection.map_window(id).unwrap().check().unwrap();
    let gc=connection.generate_id().unwrap();
    connection.create_gc(gc,id,&CreateGCAux::new().foreground(color)).unwrap().check().unwrap();
    connection.poly_fill_rectangle(id,gc,&[Rectangle{x:0,y:0,width:220,height:140}]).unwrap().check().unwrap();
    connection.free_gc(gc).unwrap().check().unwrap();
}
fn focus(connection:&XConnection,window:Window) {
    connection.stream().budget(REQUEST_BUDGET).unwrap();
    connection.set_input_focus(InputFocus::PARENT,window,x11rb::CURRENT_TIME).unwrap().check().unwrap();
}
fn drain(connection:&XConnection)->Vec<Event> {
    connection.stream().budget(REQUEST_BUDGET).unwrap();
    connection.get_input_focus().unwrap().reply().unwrap();
    let mut events=Vec::new();
    while let Some(event)=connection.poll_for_event().unwrap(){events.push(event);}
    events
}
fn options()->SnapshotOptions {SnapshotOptions {tree:true,screenshot:true,interactive:false,maximum:80}}

#[test]
fn isolated_x11_capture_actions_and_replacement_stay_on_the_approved_window() {
    let server=Server::start();let connection=server.connection();let root=connection.setup().roots[0].root;
    let target=connection.generate_id().unwrap();let excluded=connection.generate_id().unwrap();
    create(&connection,root,target,"Approved fixture",0xff0000,true);
    // This opaque green sibling covers the red selected window. A root crop
    // would expose the sibling; the named selected-window pixmap stays red.
    create(&connection,root,excluded,"EXCLUDED PRIVATE FIXTURE",0x00ff00,false);
    focus(&connection,target);
    let mut native=Native::from_connection(&selected(&server.number),server.connection(),0).unwrap();
    let snapshot=native.snapshot(options()).unwrap();
    assert_eq!(snapshot.elements.len(),1);
    assert_eq!(snapshot.elements[0]["name"],"Approved fixture");
    assert!(!serde_json::to_string(&snapshot.elements).unwrap().contains("EXCLUDED"));
    assert_eq!(snapshot.screenshot_status,"captured_selected_window_pixmap");
    let red=std::iter::repeat_n([255u8,0,0],220*140).flatten().collect::<Vec<_>>();
    assert_eq!(snapshot.screenshot.unwrap(),image::png(220,140,&red).unwrap());
    drain(&connection);
    let result=native.action(&Action::Click{selector:"control:1".into()}).unwrap();
    assert_eq!(result["dispatched"],true);assert_eq!(result["effect_verified"],false);
    let events=drain(&connection);
    let buttons=events.iter().filter_map(|event|match event {Event::ButtonPress(event)=>Some((event.event,event.response_type)),Event::ButtonRelease(event)=>Some((event.event,event.response_type)),_=>None}).collect::<Vec<_>>();
    assert_eq!(buttons.len(),2);
    assert!(buttons.iter().all(|(window,kind)|*window==target&&kind&0x80!=0));
    native.snapshot(options()).unwrap();
    native.action(&Action::SendKeys{selector:"control:1".into(),keys:"Enter".into()}).unwrap();
    let events=drain(&connection);
    let keys=events.iter().filter_map(|event|match event {Event::KeyPress(event)=>Some(event.event),Event::KeyRelease(event)=>Some(event.event),_=>None}).collect::<Vec<_>>();
    assert_eq!(keys,vec![target,target]);
    focus(&connection,excluded);
    assert_eq!(native.inspect().err().unwrap().to_string(),"WINDOW_FOREGROUND_REQUIRED");
    focus(&connection,target);
    native.snapshot(options()).unwrap();
    connection.destroy_window(target).unwrap().check().unwrap();
    create(&connection,root,target,"Approved fixture",0xff0000,true);
    focus(&connection,target);
    assert_eq!(native.action(&Action::Click{selector:"control:1".into()}).unwrap_err().to_string(),"WINDOW_IDENTITY_CHANGED");
    assert!(native.inspect().is_err(),"same XID/title/process must not renew consent after destruction");
}

#[test]
fn isolated_x11_uncomposited_and_foreign_children_fail_without_capture_fallback() {
    let server=Server::start();let connection=server.connection();let root=connection.setup().roots[0].root;
    let target=connection.generate_id().unwrap();
    create(&connection,root,target,"Approved fixture",0xff0000,false);focus(&connection,target);
    let mut native=Native::from_connection(&selected(&server.number),server.connection(),0).unwrap();
    let snapshot=native.snapshot(options()).unwrap();
    assert!(snapshot.screenshot.is_none());
    assert_eq!(snapshot.screenshot_status,"unsupported_window_not_composited");
    let mut foreign=Foreign::start(&server.number,target);
    assert_eq!(native.snapshot(options()).err().unwrap().to_string(),"WINDOW_FOREIGN_CHILD_REFUSED");
    foreign.stop();
}

#[test]
fn isolated_x11_watchdog_releases_other_clients_without_any_grabber_io(){
    let server=Server::start();let grabbing=server.connection();let peer=server.connection();
    let guard=grab(&grabbing).unwrap();
    let(send,receive)=std::sync::mpsc::channel();
    let waiting=std::thread::spawn(move||{
        let result=peer.get_input_focus().map_err(unavailable).and_then(|cookie|cookie.reply().map_err(unavailable));
        let _=send.send(result);
    });
    // Keep guard alive and perform no I/O on its connection. This models an
    // unrelated filesystem stall inside a scoped operation. Only the separate
    // watchdog can release the server in time for this other client to reply.
    receive.recv_timeout(Duration::from_secs(2)).expect("watchdog must release X independently of the calling thread").unwrap();
    assert!(grabbing.stream().dead.load(Ordering::SeqCst));
    assert!(grabbing.stream().budget(REQUEST_BUDGET).is_err(),"expired connection cannot be revived");
    drop(guard);waiting.join().unwrap();
    let healthy=server.connection();drop(grab(&healthy).unwrap());
    healthy.stream().budget(REQUEST_BUDGET).unwrap();
    healthy.get_input_focus().unwrap().reply().unwrap();
}

struct Foreign { child:Child }
impl Foreign {
    fn start(display:&str,parent:Window)->Self {
        let child=Command::new(std::env::current_exe().unwrap())
            .args(["--exact","window_inspection::portable::native::tests::x11_foreign_child_fixture","--ignored","--nocapture"])
            .env("AGENT_BRIDGE_TEST_X11_DISPLAY",display).env("AGENT_BRIDGE_TEST_X11_PARENT",parent.to_string())
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let mut fixture=Self{child};let output=fixture.child.stdout.take().unwrap();
        let (send,receive)=std::sync::mpsc::channel();
        std::thread::spawn(move||{for line in std::io::BufReader::new(output).lines(){if line.ok().as_deref()==Some("X11_FOREIGN_READY"){let _=send.send(());}}});
        receive.recv_timeout(Duration::from_secs(5)).expect("foreign process did not create its fixture child");fixture
    }
    fn stop(&mut self){
        if let Some(mut input)=self.child.stdin.take(){let _=input.write_all(b"x");}
        let deadline=Instant::now()+Duration::from_secs(2);
        loop {match self.child.try_wait(){Ok(Some(status))=>{assert!(status.success());return;},Ok(None) if Instant::now()<deadline=>std::thread::sleep(Duration::from_millis(10)),_=>panic!("owned foreign fixture did not exit")}}
    }
}
impl Drop for Foreign {fn drop(&mut self){let _=self.child.kill();let _=self.child.wait();}}

#[test]
#[ignore="child fixture invoked only by the isolated X11 regression"]
fn x11_foreign_child_fixture() {
    let number=std::env::var("AGENT_BRIDGE_TEST_X11_DISPLAY").unwrap().parse::<u16>().unwrap();
    let parent=std::env::var("AGENT_BRIDGE_TEST_X11_PARENT").unwrap().parse::<u32>().unwrap();
    let connection=test_connection(number);let child=connection.generate_id().unwrap();
    create(&connection,parent,child,"FOREIGN SECRET",0x0000ff,false);
    println!("X11_FOREIGN_READY");std::io::stdout().flush().unwrap();
    let _=std::io::stdin().read(&mut [0u8;1]);
}
