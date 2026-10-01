//! The sessions shown in the window, and the commands the front end drives
//! them with.
//!
//! The front end picks an id for each session and passes a channel to
//! `ssh_connect`. Everything the backend has to say about that session then
//! arrives on the channel, in order: terminal output as raw bytes, the rest
//! as [`UiEvent`]s.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use poderosov_core::known_hosts::{HostKeyStatus, KnownHosts};
use poderosov_core::session::{CloseReason, SessionEvent, SessionHandle, TerminalSize};
use poderosov_core::ssh::{self, HostKeyPrompt, HostKeyPrompter, SshAuth, SshError, SshParams};
use serde::{Deserialize, Serialize};
use tauri::ipc::{Channel, InvokeResponseBody};
use tauri::{AppHandle, Manager, State};
use tokio::sync::{Notify, mpsc, oneshot};

/// Session events waiting between the SSH task and the task feeding the webview.
const EVENT_QUEUE: usize = 16;

/// The most terminal output put into one message to the webview.
const MAX_BATCH: usize = 64 * 1024;

/// How much output the webview may have been sent without reporting it
/// drawn. Past this, nothing more is read from the server until it catches up.
const HIGH_WATERMARK: usize = 512 * 1024;

/// Every session that is open or being opened, by the id the front end gave it.
#[derive(Default)]
pub struct Sessions(Mutex<HashMap<u32, Entry>>);

#[derive(Default)]
struct Entry {
    /// While connecting: dropping this abandons the attempt.
    cancel: Option<oneshot::Sender<()>>,
    /// While the user is looking at a host key prompt: takes the answer.
    host_key_answer: Option<oneshot::Sender<bool>>,
    /// Once the shell is running.
    handle: Option<SessionHandle>,
    flow: Arc<FlowControl>,
}

impl Sessions {
    fn lock(&self) -> MutexGuard<'_, HashMap<u32, Entry>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn handle(&self, id: u32) -> Option<SessionHandle> {
        self.lock().get(&id)?.handle.clone()
    }

    fn write(&self, id: u32, data: Vec<u8>) {
        // Input for a session that has just ended has nowhere to go.
        if let Some(handle) = self.handle(id) {
            let _ = handle.write(data);
        }
    }
}

/// Keeps output from being sent to the webview faster than it can draw it.
#[derive(Default)]
struct FlowControl {
    /// Bytes sent to the webview that it has not reported as drawn.
    unacknowledged: AtomicUsize,
    /// Set when the session is closed from the window: nothing waits after that.
    released: AtomicBool,
    changed: Notify,
}

impl FlowControl {
    fn sent(&self, bytes: usize) {
        self.unacknowledged.fetch_add(bytes, Ordering::Relaxed);
    }

    fn acknowledged(&self, bytes: usize) {
        let _ = self
            .unacknowledged
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |unacknowledged| {
                Some(unacknowledged.saturating_sub(bytes))
            });
        self.changed.notify_one();
    }

    fn release(&self) {
        self.released.store(true, Ordering::Relaxed);
        self.changed.notify_one();
    }

    /// Waits until the webview has caught up enough to be sent more.
    async fn room(&self) {
        while self.unacknowledged.load(Ordering::Relaxed) > HIGH_WATERMARK
            && !self.released.load(Ordering::Relaxed)
        {
            self.changed.notified().await;
        }
    }
}

/// What the login dialog collected.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectRequest {
    host: String,
    port: u16,
    user: String,
    auth: AuthRequest,
    term: String,
    cols: u32,
    rows: u32,
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AuthRequest {
    Password { password: String },
    PublicKey { key_path: PathBuf, passphrase: String },
}

impl From<ConnectRequest> for SshParams {
    fn from(request: ConnectRequest) -> Self {
        let auth = match request.auth {
            AuthRequest::Password { password } => SshAuth::Password(password),
            AuthRequest::PublicKey { key_path, passphrase } => SshAuth::PublicKey {
                key_path,
                // the dialog has one field; left empty it means the key is not encrypted
                passphrase: Some(passphrase).filter(|passphrase| !passphrase.is_empty()),
            },
        };
        SshParams {
            host: request.host,
            port: request.port,
            user: request.user,
            auth,
            term: request.term,
            size: TerminalSize { cols: request.cols, rows: request.rows },
        }
    }
}

/// What is sent on a session's channel besides terminal output.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
enum UiEvent<'a> {
    /// The user has to decide about a host key. Answered with `host_key_reply`.
    HostKey {
        host: &'a str,
        port: u16,
        algorithm: &'a str,
        fingerprint: &'a str,
        /// The key differs from the one on record, rather than being new.
        changed: bool,
    },
    /// The session is over. `error` is set unless it ended in an orderly way.
    Closed { error: Option<String> },
}

fn send_event(channel: &Channel<InvokeResponseBody>, event: &UiEvent<'_>) -> tauri::Result<()> {
    channel.send(InvokeResponseBody::Json(serde_json::to_string(event)?))
}

/// Why `ssh_connect` failed. The front end words the message from `kind`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectFailure {
    kind: FailureKind,
    /// What the OS or the SSH library had to say, if anything.
    detail: String,
    /// After a failed login: the methods the server would still accept.
    methods: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum FailureKind {
    Cancelled,
    Connect,
    Timeout,
    HostKeyRejected,
    KnownHosts,
    PrivateKey,
    AuthFailed,
    PtyRefused,
    Protocol,
}

impl ConnectFailure {
    fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self { kind, detail: detail.into(), methods: Vec::new() }
    }

    fn cancelled() -> Self {
        Self::new(FailureKind::Cancelled, "")
    }
}

impl From<SshError> for ConnectFailure {
    fn from(error: SshError) -> Self {
        match error {
            SshError::Connect { source, .. } => Self::new(FailureKind::Connect, source.to_string()),
            SshError::ConnectTimeout { .. } => Self::new(FailureKind::Timeout, ""),
            SshError::HostKeyRejected => Self::new(FailureKind::HostKeyRejected, ""),
            SshError::KnownHosts(source) => Self::new(FailureKind::KnownHosts, source.to_string()),
            SshError::PrivateKey(source) => Self::new(FailureKind::PrivateKey, source.to_string()),
            SshError::AuthFailed { methods } => Self {
                kind: FailureKind::AuthFailed,
                detail: String::new(),
                methods,
            },
            SshError::PtyRefused => Self::new(FailureKind::PtyRefused, ""),
            SshError::Protocol(source) => Self::new(FailureKind::Protocol, source.to_string()),
        }
    }
}

/// Puts a host key question to the user through the session's channel.
struct WindowPrompter {
    app: AppHandle,
    id: u32,
    on_event: Channel<InvokeResponseBody>,
}

impl HostKeyPrompter for WindowPrompter {
    async fn confirm(&mut self, prompt: HostKeyPrompt) -> bool {
        let (answer_tx, answer_rx) = oneshot::channel();
        {
            let sessions = self.app.state::<Sessions>();
            let mut sessions = sessions.lock();
            let Some(entry) = sessions.get_mut(&self.id) else {
                return false;
            };
            entry.host_key_answer = Some(answer_tx);
        }
        let asked = send_event(
            &self.on_event,
            &UiEvent::HostKey {
                host: &prompt.host,
                port: prompt.port,
                algorithm: &prompt.algorithm,
                fingerprint: &prompt.fingerprint,
                changed: prompt.status == HostKeyStatus::Changed,
            },
        );
        if asked.is_err() {
            return false;
        }
        // An answer that never comes because the attempt was abandoned is a no.
        answer_rx.await.unwrap_or(false)
    }
}

fn known_hosts(app: &AppHandle) -> Result<KnownHosts, ConnectFailure> {
    let directory = app
        .path()
        .app_config_dir()
        .map_err(|error| ConnectFailure::new(FailureKind::KnownHosts, error.to_string()))?;
    Ok(KnownHosts::new(directory.join("ssh_known_hosts")))
}

/// Opens an SSH session. Resolves once the shell is running; until then
/// `session_close` abandons the attempt.
#[tauri::command]
pub async fn ssh_connect(
    app: AppHandle,
    sessions: State<'_, Sessions>,
    id: u32,
    request: ConnectRequest,
    on_event: Channel<InvokeResponseBody>,
) -> Result<(), ConnectFailure> {
    let known_hosts = known_hosts(&app)?;
    let flow = Arc::new(FlowControl::default());
    let (cancel_tx, cancel_rx) = oneshot::channel();
    sessions.lock().insert(
        id,
        Entry {
            cancel: Some(cancel_tx),
            flow: flow.clone(),
            ..Default::default()
        },
    );

    let prompter = WindowPrompter {
        app: app.clone(),
        id,
        on_event: on_event.clone(),
    };
    let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
    let result = tokio::select! {
        result = ssh::connect(request.into(), known_hosts, prompter, events_tx) => {
            result.map_err(ConnectFailure::from)
        }
        // fires when `session_close` drops the entry
        _ = cancel_rx => Err(ConnectFailure::cancelled()),
    };

    let handle = match result {
        Ok(handle) => handle,
        Err(failure) => {
            sessions.lock().remove(&id);
            return Err(failure);
        }
    };
    {
        let mut sessions = sessions.lock();
        let Some(entry) = sessions.get_mut(&id) else {
            // closed just as the shell came up
            handle.close();
            return Err(ConnectFailure::cancelled());
        };
        entry.cancel = None;
        entry.handle = Some(handle);
    }
    tauri::async_runtime::spawn(forward_events(app, id, events_rx, on_event, flow));
    Ok(())
}

/// Passes a session's output and its end on to the webview.
async fn forward_events(
    app: AppHandle,
    id: u32,
    mut events: mpsc::Receiver<SessionEvent>,
    on_event: Channel<InvokeResponseBody>,
    flow: Arc<FlowControl>,
) {
    let mut closed = None;
    while closed.is_none() {
        flow.room().await;
        let mut batch = match events.recv().await {
            Some(SessionEvent::Data(data)) => Vec::from(data),
            Some(SessionEvent::Closed(reason)) => {
                closed = Some(reason);
                break;
            }
            None => break,
        };
        // One message per packet would swamp the webview during a flood of
        // output, so whatever else is already waiting goes out with it.
        while batch.len() < MAX_BATCH {
            match events.try_recv() {
                Ok(SessionEvent::Data(data)) => batch.extend_from_slice(&data),
                Ok(SessionEvent::Closed(reason)) => {
                    closed = Some(reason);
                    break;
                }
                Err(_) => break,
            }
        }
        flow.sent(batch.len());
        if on_event.send(InvokeResponseBody::Raw(batch)).is_err() {
            // the window is gone
            break;
        }
    }

    if let Some(reason) = closed {
        let error = match reason {
            CloseReason::Error(message) => Some(message),
            CloseReason::Exited(_) | CloseReason::ClosedByUser => None,
        };
        let _ = send_event(&on_event, &UiEvent::Closed { error });
    }
    app.state::<Sessions>().lock().remove(&id);
}

/// The user's answer to a host key prompt.
#[tauri::command]
pub fn host_key_reply(sessions: State<'_, Sessions>, id: u32, accept: bool) {
    let answer = sessions
        .lock()
        .get_mut(&id)
        .and_then(|entry| entry.host_key_answer.take());
    if let Some(answer) = answer {
        let _ = answer.send(accept);
    }
}

/// Typed or pasted text.
#[tauri::command]
pub fn session_write(sessions: State<'_, Sessions>, id: u32, data: String) {
    sessions.write(id, data.into_bytes());
}

/// Input that is not text, such as the mouse reports of some terminal modes.
#[tauri::command]
pub fn session_write_bytes(sessions: State<'_, Sessions>, id: u32, data: Vec<u8>) {
    sessions.write(id, data);
}

#[tauri::command]
pub fn session_resize(sessions: State<'_, Sessions>, id: u32, cols: u32, rows: u32) {
    if let Some(handle) = sessions.handle(id) {
        let _ = handle.resize(TerminalSize { cols, rows });
    }
}

/// The webview has drawn this much more of the output it was sent.
#[tauri::command]
pub fn session_ack(sessions: State<'_, Sessions>, id: u32, bytes: usize) {
    if let Some(entry) = sessions.lock().get(&id) {
        entry.flow.acknowledged(bytes);
    }
}

/// Closes a session, or abandons it if it is still connecting.
#[tauri::command]
pub fn session_close(sessions: State<'_, Sessions>, id: u32) {
    let entry = sessions.lock().remove(&id);
    if let Some(entry) = entry {
        entry.flow.release();
        if let Some(handle) = entry.handle {
            handle.close();
        }
    }
}
