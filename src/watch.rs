//! `omgs watch`: a loopback-only server for the optional progress dashboard.
//!
//! It serves exactly two read-only routes, the embedded dashboard and the run's
//! `pipeline-status.json`, never the rest of the run directory (findings and
//! reports describe vulnerabilities). It binds 127.0.0.1 on an ephemeral port,
//! rejects foreign Host headers so a rebinding page cannot read it, never opens
//! a browser, and exits once the run is marked complete.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

const DASHBOARD: &str = include_str!("../skill/progress/dashboard.html");
const MAX_REQUEST: usize = 8 * 1024;
/// How long the page keeps updating after the run completes, so the final
/// state is visible before the server goes away.
const COMPLETE_GRACE: Duration = Duration::from_secs(10);

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    }
}

fn text(status: u16) -> Response {
    Response {
        status,
        content_type: "text/plain; charset=utf-8",
        body: reason(status).as_bytes().to_vec(),
    }
}

/// Answer one raw request. Pure apart from reading the status file, so the
/// routing and Host rules are testable without a socket.
pub fn respond(raw: &str, port: u16, run_dir: &Path) -> Response {
    let mut lines = raw.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return text(400);
    };
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return text(400);
    }
    let mut hosts = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.trim().to_ascii_lowercase());
    let host = hosts.next();
    let allowed = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    if hosts.next().is_some() || !host.is_some_and(|h| allowed.contains(&h)) {
        return text(403);
    }
    if method != "GET" {
        return text(405);
    }
    let path = target.split('?').next().unwrap_or_default();
    match path {
        "/" | "/dashboard.html" => Response {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: DASHBOARD.as_bytes().to_vec(),
        },
        "/pipeline-status.json" => {
            let body = match crate::review::View::load(run_dir)
                .and_then(|view| serde_json::to_vec(&view.progress).map_err(|e| e.to_string()))
            {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Response {
                        status: 500,
                        content_type: "text/plain; charset=utf-8",
                        body: b"Invalid run artifact: pipeline-status.json".to_vec(),
                    }
                }
            };
            Response {
                status: 200,
                content_type: "application/json",
                body,
            }
        }
        _ => text(404),
    }
}

/// Write all of `bytes` before `deadline`, or give up. A reader that drains
/// slowly cannot stretch one response past the request deadline.
fn write_until(stream: &mut TcpStream, mut bytes: &[u8], deadline: Instant) -> bool {
    while !bytes.is_empty() {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return false;
        };
        let _ = stream.set_write_timeout(Some(left));
        match stream.write(bytes) {
            Ok(0) | Err(_) => return false,
            Ok(n) => bytes = &bytes[n..],
        }
    }
    true
}

fn write_response(stream: &mut TcpStream, r: &Response, deadline: Instant) {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    if write_until(stream, head.as_bytes(), deadline) {
        write_until(stream, &r.body, deadline);
    }
}

/// Total time one connection may take to send its request, so a client that
/// trickles bytes cannot hold the single server thread.
const REQUEST_DEADLINE: Duration = Duration::from_secs(2);

fn handle(mut stream: TcpStream, port: u16, run_dir: &Path) {
    // One absolute deadline covers reading the request and writing the reply.
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return;
        };
        let _ = stream.set_read_timeout(Some(left));
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_REQUEST {
                    write_response(&mut stream, &text(400), deadline);
                    return;
                }
            }
        }
    }
    let raw = String::from_utf8_lossy(&buf);
    write_response(&mut stream, &respond(&raw, port, run_dir), deadline);
}

/// Bind loopback and return the listener with its port, so callers can print
/// the URL before serving.
pub fn bind() -> Result<(TcpListener, u16), String> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind 127.0.0.1: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok((listener, port))
}

/// Serve until the run is complete (plus a short grace) or `max` elapses.
pub fn serve(listener: TcpListener, port: u16, run_dir: &Path, max: Duration) {
    let start = Instant::now();
    let mut completed_at: Option<Instant> = None;
    let mut last_check = Instant::now() - Duration::from_secs(1);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                handle(stream, port, run_dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        if last_check.elapsed() >= Duration::from_millis(500) {
            last_check = Instant::now();
            if completed_at.is_none() && crate::runmeta::is_complete(run_dir) {
                completed_at = Some(Instant::now());
            }
        }
        if completed_at.is_some_and(|t| t.elapsed() >= COMPLETE_GRACE) || start.elapsed() >= max {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
