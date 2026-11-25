use agent_bridge_http::{
    bind_loopback, serve_managed, validate_loopback_listener, HealthStatus, HttpServerConfig,
    ServiceActivity,
};
use serde_json::json;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener as StdTcpListener, TcpStream};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn pick_free_port() -> u16 {
    let l = StdTcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind ephemeral port");
    l.local_addr().unwrap().port()
}

fn send_http(port: u16, raw_request: &str) -> String {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect loopback");
    stream.write_all(raw_request.as_bytes()).expect("write request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read response");
    resp
}

#[test]
fn http_loopback_only_health_mcp_accept_header_and_shutdown_regressions() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async {
        // Port 0 MUST be rejected
        assert!(bind_loopback(0).await.is_err());

        // IPv6 loopback listener MUST be rejected by validate_loopback_listener
        if let Ok(v6) = TcpListener::bind(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))).await {
            assert!(validate_loopback_listener(&v6).is_err());
        }

        let port = pick_free_port();
        let listener = bind_loopback(port).await.expect("bind explicit loopback port");
        let bound = validate_loopback_listener(&listener).expect("validate ipv4 loopback");
        assert_eq!(bound.port(), port);

        let activity = ServiceActivity::default();
        assert!(activity.is_idle());

        let (tx, rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn(serve_managed(
            listener,
            HttpServerConfig::default(),
            activity.clone(),
            |body| Some(json!({"jsonrpc": "2.0", "id": 1, "result": {"echo_len": body.len()}}).to_string()),
            || HealthStatus::ok().with_details(json!({"backend": "rust"})),
            async move {
                let _ = rx.await;
            },
        ));

        tokio::task::yield_now().await;
        // 1. GET /health -> 200 OK
        let h = tokio::task::spawn_blocking(move || {
            send_http(port, &format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"))
        })
        .await
        .unwrap();
        assert!(h.starts_with("HTTP/1.1 200"), "unexpected /health: {h}");
        assert!(h.contains("rust"), "missing details in /health: {h}");

        // 2. POST /mcp WITHOUT Accept: application/json -> rejected (4xx)
        let no_acc = tokio::task::spawn_blocking(move || {
            let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
            send_http(
                port,
                &format!(
                    "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
            )
        })
        .await
        .unwrap();
        assert!(no_acc.contains("missing_accept") || no_acc.starts_with("HTTP/1.1 4"), "{no_acc}");

        // 3. POST /mcp WITH Accept: application/json -> 200 OK with dispatched payload
        let ok_mcp = tokio::task::spawn_blocking(move || {
            let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
            send_http(
                port,
                &format!(
                    "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
            )
        })
        .await
        .unwrap();
        assert!(ok_mcp.starts_with("HTTP/1.1 200"), "{ok_mcp}");
        assert!(ok_mcp.contains("echo_len"), "{ok_mcp}");

        // 4. GET /mcp -> 405 Method Not Allowed; GET /unknown -> 404
        let m405 = tokio::task::spawn_blocking(move || {
            send_http(port, &format!("GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"))
        })
        .await
        .unwrap();
        assert!(m405.starts_with("HTTP/1.1 405"), "{m405}");

        let n404 = tokio::task::spawn_blocking(move || {
            send_http(port, &format!("GET /does-not-exist HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"))
        })
        .await
        .unwrap();
        assert!(n404.starts_with("HTTP/1.1 404"), "{n404}");

        // 5. Graceful shutdown drains cleanly
        let _ = tx.send(());
        server_task.await.unwrap().expect("graceful shutdown ok");
    });
}
