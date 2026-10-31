//! `omgs watch`: a loopback-only server for the optional progress dashboard.
//!
//! It serves exactly two read-only routes, the embedded dashboard and the run's
//! `pipeline-status.json`, never the rest of the run directory (findings and
//! reports describe vulnerabilities). It binds 127.0.0.1 on an ephemeral port,
//! rejects foreign Host headers so a rebinding page cannot read it, never opens
//! a browser, and exits once the run is marked complete. Status requires the
//! per-run token printed only to the starting terminal, sent by the dashboard
//! in an `X-OMGS-Token` header, so other local users and processes cannot
//! read it. The status is a fixed projection that never carries finding,
//! lead or other free text written by agents.

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
pub fn respond(raw: &str, port: u16, token: &str, run_dir: &Path) -> Response {
    respond_locked(raw, port, token, run_dir)
}

/// Constant-time comparison, so response timing reveals nothing about the token.
fn same_token(given: &str, token: &str) -> bool {
    given.len() == token.len()
        && given
            .bytes()
            .zip(token.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn respond_locked(raw: &str, port: u16, token: &str, run_dir: &Path) -> Response {
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
    let headers: Vec<(String, String)> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let mut hosts = headers
        .iter()
        .filter(|(k, _)| k == "host")
        .map(|(_, v)| v.to_ascii_lowercase());
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
            let mut given = headers.iter().filter(|(k, _)| k == "x-omgs-token");
            let authorized = match (given.next(), given.next()) {
                (Some((_, value)), None) => !token.is_empty() && same_token(value, token),
                _ => false,
            };
            if !authorized {
                return text(403);
            }
            let body = match crate::runmeta::with_lock(run_dir, || {
                // Unsafe file types are refused. Parse errors in regular artifacts
                // become review limits in the canonical progress document.
                crate::run_artifact::optional_text(
                    run_dir,
                    Path::new(crate::status::FILE),
                    crate::run_artifact::STATUS_BYTES,
                )?;
                crate::review::View::load_locked(run_dir)
            })
            .and_then(|view| {
                serde_json::to_vec(&public_progress(
                    view.progress,
                    run_dir
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned()),
                ))
                .map_err(|e| e.to_string())
            }) {
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

/// Stage ids the dashboard names with its own fixed labels.
const STAGE_IDS: [&str; 9] = [
    "initialize",
    "map",
    "hunt",
    "verify",
    "challenge",
    "prove",
    "adjudicate",
    "evaluate",
    "report",
];
const STATES: [&str; 4] = ["pending", "active", "done", "failed"];
const COUNTERS: [&str; 4] = ["candidates", "confirmed", "needs_validation", "rejected"];

fn state_of(v: &serde_json::Value) -> &'static str {
    let s = v.as_str().unwrap_or_default();
    STATES
        .iter()
        .find(|k| **k == s)
        .copied()
        .unwrap_or("pending")
}

/// One stage with only fixed vocabulary, numbers and generic labels.
fn public_stage(stage: &serde_json::Value, label: String) -> serde_json::Value {
    let id = stage.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    let known = STAGE_IDS.contains(&id);
    let mut out = serde_json::json!({
        "id": if known { id } else { "step" },
        "label": label,
        "status": state_of(&stage["status"]),
    });
    for key in ["started_ms", "ended_ms"] {
        if let Some(n) = stage.get(key).and_then(|v| v.as_u64()) {
            out[key] = n.into();
        }
    }
    if let Some(children) = stage.get("children").and_then(|v| v.as_array()) {
        out["children"] = children
            .iter()
            .enumerate()
            .map(|(i, c)| public_stage(c, format!("Part {}", i + 1)))
            .collect();
    }
    out
}

/// The live view shows progress, never review content. It is an explicit
/// projection: stage ids from a fixed list, states, times, numeric
/// counters, fixed sentences and the run directory name. Stage details, labels, log messages,
/// history and gap messages are agent or target text that can quote
/// findings, so none of it is served.
fn public_progress(progress: serde_json::Value, run_name: Option<String>) -> serde_json::Value {
    let stages: Vec<serde_json::Value> = progress
        .get("stages")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .enumerate()
                .map(|(i, st)| public_stage(st, format!("Review step {}", i + 1)))
                .collect()
        })
        .unwrap_or_default();
    let mut counters = serde_json::Map::new();
    for key in COUNTERS {
        if let Some(n) = progress
            .get("counters")
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_u64())
        {
            counters.insert(key.into(), n.into());
        }
    }
    let log: Vec<serde_json::Value> = progress
        .get("log")
        .and_then(|v| v.as_array())
        .map(|list| {
            list.iter()
                .map(|e| {
                    let kind = state_of(&e["kind"]);
                    serde_json::json!({
                        "ts": e
                            .get("ts")
                            .and_then(|v| v.as_str())
                            .filter(|t| t.len() <= 40 && t.bytes().all(|b| b.is_ascii_digit() || b"-:TZ.+".contains(&b)))
                            .unwrap_or_default(),
                        "kind": kind,
                        "m": match kind {
                            "active" => "A review step started",
                            "done" => "A review step finished",
                            "failed" => "A review step stopped",
                            _ => "A review step is waiting",
                        },
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let complete = progress.get("review_complete").and_then(|v| v.as_bool());
    let mut out = serde_json::json!({
        "stages": stages,
        "counters": counters,
        "log": log,
    });
    if let Some(name) = run_name {
        out["run"] = name.into();
    }
    if let Some(n) = progress.get("updated_ms").and_then(|v| v.as_u64()) {
        out["updated_ms"] = n.into();
    }
    if let Some(done) = complete {
        out["review_complete"] = done.into();
        out["review_state"] = if done {
            "complete".into()
        } else {
            "The review is incomplete. Run omgs critic and omgs validate in the run directory for details.".into()
        };
    }
    out
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

fn handle(stream: TcpStream, port: u16, token: &str, run_dir: &Path) {
    handle_inner(
        stream,
        port,
        token,
        run_dir,
        #[cfg(test)]
        || {},
    );
}

fn handle_inner(
    mut stream: TcpStream,
    port: u16,
    token: &str,
    run_dir: &Path,
    #[cfg(test)] before_write: impl FnOnce(),
) {
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
    let response = respond(&raw, port, token, run_dir);
    #[cfg(test)]
    before_write();
    write_response(&mut stream, &response, deadline);
}

/// Bind loopback and return the listener with its port and a fresh per-run
/// token, so callers can print the URL before serving.
pub fn bind() -> Result<(TcpListener, u16, String), String> {
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind 127.0.0.1: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let token = crate::platform::random_nonce().map_err(|e| format!("watch token: {e}"))?;
    Ok((listener, port, token))
}

fn update_completion(completed_at: &mut Option<Instant>, complete: bool, now: Instant) {
    if complete {
        completed_at.get_or_insert(now);
    } else {
        *completed_at = None;
    }
}

/// Serve until the run is complete (plus a short grace) or `max` elapses.
pub fn serve(listener: TcpListener, port: u16, token: &str, run_dir: &Path, max: Duration) {
    let start = Instant::now();
    let mut completed_at: Option<Instant> = None;
    let mut last_check = Instant::now() - Duration::from_secs(1);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                handle(stream, port, token, run_dir);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
        if last_check.elapsed() >= Duration::from_millis(500) {
            last_check = Instant::now();
            update_completion(
                &mut completed_at,
                crate::runmeta::is_complete(run_dir),
                Instant::now(),
            );
        }
        if completed_at.is_some_and(|t| t.elapsed() >= COMPLETE_GRACE) || start.elapsed() >= max {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn completion_grace_restarts_after_reopened_work() {
        let now = super::Instant::now();
        let mut completed = None;
        super::update_completion(&mut completed, true, now);
        super::update_completion(&mut completed, true, now + super::Duration::from_secs(2));
        assert_eq!(completed, Some(now));
        super::update_completion(&mut completed, false, now + super::Duration::from_secs(3));
        assert_eq!(completed, None);
        let later = now + super::Duration::from_secs(20);
        super::update_completion(&mut completed, true, later);
        assert_eq!(completed, Some(later));
    }
}

#[cfg(test)]
mod lock_tests {
    #[test]
    fn socket_output_and_static_dashboard_do_not_hold_the_run_lock() {
        use std::io::Write;
        let dir = crate::platform::temp_root().unwrap().join(format!(
            "omgs-watch-lock-{}",
            crate::platform::random_nonce().unwrap()
        ));
        crate::platform::create_private_dir_new(&dir).unwrap();
        crate::runmeta::with_lock(&dir, || {
            let response = super::respond(
                "GET / HTTP/1.1\r\nHost: localhost:4000\r\n\r\n",
                4000,
                "t0k",
                &dir,
            );
            assert_eq!(response.status, 200);
            Ok(())
        })
        .unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .write_all(
                format!("GET /pipeline-status.json HTTP/1.1\r\nHost: localhost:{port}\r\nX-OMGS-Token: t0k\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let (server, _) = listener.accept().unwrap();
        super::handle_inner(server, port, "t0k", &dir, || {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join(".omgs-run.lock"))
                .unwrap();
            file.try_lock()
                .expect("socket writes must begin after releasing the run lock");
        });
        drop(client);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
