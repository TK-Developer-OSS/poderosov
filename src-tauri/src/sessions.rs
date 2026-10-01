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
use std::time::{Duration, Instant};

use encoding_rs::{Decoder, Encoding, UTF_8};
use poderosov_core::known_hosts::{HostKeyStatus, KnownHosts};
use poderosov_core::session::{CloseReason, SessionEvent, SessionHandle, TerminalSize};
use poderosov_core::ssh::{self, HostKeyPrompt, HostKeyPrompter, SshAuth, SshError, SshParams};
use poderosov_core::xmodem::{Step, XmodemSender};
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

/// How often a file transfer is checked for timeouts and cancellation.
const TRANSFER_TICK: Duration = Duration::from_millis(500);

/// Every session that is open or being opened, by the id the front end gave it.
#[derive(Default)]
pub struct Sessions(Mutex<HashMap<u32, Entry>>);

struct Entry {
    /// While connecting: dropping this abandons the attempt.
    cancel: Option<oneshot::Sender<()>>,
    /// While the user is looking at a host key prompt: takes the answer.
    host_key_answer: Option<oneshot::Sender<bool>>,
    /// Once the shell is running.
    handle: Option<SessionHandle>,
    /// What the remote side reads and writes text as.
    encoding: &'static Encoding,
    flow: Arc<FlowControl>,
    transfer: Arc<Mutex<Transfer>>,
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

/// A file transfer under way on a session. While there is one, what the
/// server sends goes to it instead of the screen.
#[derive(Default)]
struct Transfer {
    sender: Option<XmodemSender>,
    cancel_requested: bool,
}

fn lock_transfer(transfer: &Mutex<Transfer>) -> MutexGuard<'_, Transfer> {
    transfer.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Passwords and key passphrases the user asked to have remembered until
/// the application exits. They are never written anywhere and never sent
/// back to the front end.
#[derive(Default)]
pub struct Passwords(Mutex<HashMap<PasswordKey, String>>);

#[derive(Hash, PartialEq, Eq)]
struct PasswordKey {
    host: String,
    port: u16,
    user: String,
    /// The key file for a passphrase, `None` for a login password.
    key_path: Option<PathBuf>,
}

impl PasswordKey {
    fn new(host: &str, port: u16, user: &str, key_path: Option<PathBuf>) -> Self {
        Self { host: host.to_ascii_lowercase(), port, user: user.to_owned(), key_path }
    }
}

impl Passwords {
    fn lock(&self) -> MutexGuard<'_, HashMap<PasswordKey, String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
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
    /// WHATWG label, e.g. `utf-8`, `euc-jp`, `shift_jis`.
    encoding: String,
    /// Keep the password (or passphrase) until the application exits.
    remember: bool,
    cols: u32,
    rows: u32,
}

#[derive(Deserialize)]
#[serde(tag = "method", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AuthRequest {
    /// Left empty, a remembered password is used.
    Password { password: String },
    PublicKey { key_path: PathBuf, passphrase: String },
}

impl AuthRequest {
    fn password_key(&self, request: &ConnectRequest) -> PasswordKey {
        let key_path = match self {
            AuthRequest::Password { .. } => None,
            AuthRequest::PublicKey { key_path, .. } => Some(key_path.clone()),
        };
        PasswordKey::new(&request.host, request.port, &request.user, key_path)
    }

    fn secret_mut(&mut self) -> &mut String {
        match self {
            AuthRequest::Password { password } => password,
            AuthRequest::PublicKey { passphrase, .. } => passphrase,
        }
    }
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
    /// How far an XMODEM upload has got.
    TransferProgress { sent: usize, total: usize },
    /// The upload is over. `error` is set unless it succeeded.
    TransferEnd { error: Option<String> },
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

    /// The password or passphrase was the problem.
    fn blames_secret(&self) -> bool {
        matches!(self.kind, FailureKind::AuthFailed | FailureKind::PrivateKey)
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

/// Whether a password (or a passphrase for `key_path`) is remembered for this login.
#[tauri::command]
pub fn password_remembered(
    passwords: State<'_, Passwords>,
    host: String,
    port: u16,
    user: String,
    key_path: Option<PathBuf>,
) -> bool {
    passwords
        .lock()
        .contains_key(&PasswordKey::new(&host, port, &user, key_path))
}

/// Opens an SSH session. Resolves once the shell is running; until then
/// `session_close` abandons the attempt.
#[tauri::command]
pub async fn ssh_connect(
    app: AppHandle,
    sessions: State<'_, Sessions>,
    passwords: State<'_, Passwords>,
    id: u32,
    mut request: ConnectRequest,
    on_event: Channel<InvokeResponseBody>,
) -> Result<(), ConnectFailure> {
    let known_hosts = known_hosts(&app)?;
    let encoding = Encoding::for_label(request.encoding.as_bytes()).unwrap_or(UTF_8);

    // An empty field means: use what was remembered, if anything was.
    let password_key = request.auth.password_key(&request);
    let remember = request.remember;
    let mut used_remembered = false;
    if request.auth.secret_mut().is_empty() {
        if let Some(remembered) = passwords.lock().get(&password_key) {
            *request.auth.secret_mut() = remembered.clone();
            used_remembered = true;
        }
    }
    let secret = request.auth.secret_mut().clone();

    let flow = Arc::new(FlowControl::default());
    let transfer = Arc::new(Mutex::new(Transfer::default()));
    let (cancel_tx, cancel_rx) = oneshot::channel();
    sessions.lock().insert(
        id,
        Entry {
            cancel: Some(cancel_tx),
            host_key_answer: None,
            handle: None,
            encoding,
            flow: flow.clone(),
            transfer: transfer.clone(),
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
            // a remembered password that no longer works is forgotten
            if used_remembered && failure.blames_secret() {
                passwords.lock().remove(&password_key);
            }
            return Err(failure);
        }
    };
    {
        let mut passwords = passwords.lock();
        if remember && !secret.is_empty() {
            passwords.insert(password_key, secret);
        } else if !remember {
            passwords.remove(&password_key);
        }
    }
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
    let forwarder = Forwarder { app, id, on_event, flow, transfer, encoding };
    tauri::async_runtime::spawn(forwarder.run(events_rx));
    Ok(())
}

/// Passes a session's output and its end on to the webview, or to a file
/// transfer while one is under way.
struct Forwarder {
    app: AppHandle,
    id: u32,
    on_event: Channel<InvokeResponseBody>,
    flow: Arc<FlowControl>,
    transfer: Arc<Mutex<Transfer>>,
    encoding: &'static Encoding,
}

impl Forwarder {
    async fn run(self, mut events: mpsc::Receiver<SessionEvent>) {
        // UTF-8 goes through untouched: the terminal decodes it itself.
        let mut decoder = (self.encoding != UTF_8).then(|| self.encoding.new_decoder());
        let mut ticker = tokio::time::interval(TRANSFER_TICK);
        let mut closed = None;

        while closed.is_none() {
            let transferring = lock_transfer(&self.transfer).sender.is_some();
            let event = tokio::select! {
                event = next_event(&mut events, &self.flow, transferring) => event,
                _ = ticker.tick(), if transferring => {
                    self.tick_transfer();
                    continue;
                }
            };
            let mut batch = match event {
                Some(SessionEvent::Data(data)) => Vec::from(data),
                Some(SessionEvent::Closed(reason)) => {
                    closed = Some(reason);
                    break;
                }
                None => break,
            };
            // asked again: the transfer may have started while we were waiting
            if lock_transfer(&self.transfer).sender.is_some() {
                // what comes after the end of the transfer, e.g. the prompt, goes on screen
                let used = self.feed_transfer(&batch);
                batch.drain(..used);
                if batch.is_empty() {
                    continue;
                }
            }
            // One message per packet would swamp the webview during a flood
            // of output, so whatever else is already waiting goes out with it.
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
            if let Some(decoder) = decoder.as_mut() {
                batch = decode(decoder, &batch);
            }
            self.flow.sent(batch.len());
            if self.on_event.send(InvokeResponseBody::Raw(batch)).is_err() {
                // the window is gone
                break;
            }
        }

        if let Some(reason) = closed {
            let error = match reason {
                CloseReason::Error(message) => Some(message),
                CloseReason::Exited(_) | CloseReason::ClosedByUser => None,
            };
            let _ = send_event(&self.on_event, &UiEvent::Closed { error });
        }
        self.app.state::<Sessions>().lock().remove(&self.id);
    }

    /// Hands output to the transfer; returns how much of it the transfer used.
    fn feed_transfer(&self, input: &[u8]) -> usize {
        let (steps, used) = match lock_transfer(&self.transfer).sender.as_mut() {
            Some(sender) => sender.receive_until_over(input, Instant::now()),
            None => return 0,
        };
        self.apply(steps);
        used
    }

    fn tick_transfer(&self) {
        let steps = {
            let mut transfer = lock_transfer(&self.transfer);
            let cancel = std::mem::take(&mut transfer.cancel_requested);
            match transfer.sender.as_mut() {
                Some(sender) if cancel => sender.cancel(),
                Some(sender) => sender.tick(Instant::now()),
                None => return,
            }
        };
        self.apply(steps);
    }

    fn apply(&self, steps: Vec<Step>) {
        for step in steps {
            match step {
                Step::Send(bytes) => self.app.state::<Sessions>().write(self.id, bytes),
                Step::Progress { sent, total } => {
                    let _ = send_event(&self.on_event, &UiEvent::TransferProgress { sent, total });
                }
                Step::Finished => self.end_transfer(None),
                Step::Failed(reason) => self.end_transfer(Some(reason)),
            }
        }
    }

    fn end_transfer(&self, error: Option<String>) {
        *lock_transfer(&self.transfer) = Transfer::default();
        let _ = send_event(&self.on_event, &UiEvent::TransferEnd { error });
    }
}

/// The next session event, once the webview has room for more output.
/// During a transfer the output does not go to the webview, so it never waits.
async fn next_event(
    events: &mut mpsc::Receiver<SessionEvent>,
    flow: &FlowControl,
    transferring: bool,
) -> Option<SessionEvent> {
    if !transferring {
        flow.room().await;
    }
    events.recv().await
}

/// Turns output in the session's encoding into UTF-8. A character split
/// between two packets is held back until the rest of it arrives.
fn decode(decoder: &mut Decoder, input: &[u8]) -> Vec<u8> {
    let capacity = decoder
        .max_utf8_buffer_length(input.len())
        .unwrap_or(input.len() * 3);
    let mut output = String::with_capacity(capacity);
    let _ = decoder.decode_to_string(input, &mut output, false);
    output.into_bytes()
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

/// Typed or pasted text, sent in the session's encoding.
#[tauri::command]
pub fn session_write(sessions: State<'_, Sessions>, id: u32, data: String) {
    let encoding = match sessions.lock().get(&id) {
        Some(entry) => entry.encoding,
        None => return,
    };
    let (bytes, _, _) = encoding.encode(&data);
    sessions.write(id, bytes.into_owned());
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

/// Starts uploading a file with XMODEM. The remote side should already be
/// waiting for it, e.g. in `rx filename`. Returns the file's size.
#[tauri::command]
pub fn xmodem_send(sessions: State<'_, Sessions>, id: u32, path: PathBuf) -> Result<usize, String> {
    let transfer = match sessions.lock().get(&id) {
        Some(entry) if entry.handle.is_some() => entry.transfer.clone(),
        _ => return Err("the session is not open".to_owned()),
    };
    let data = std::fs::read(&path).map_err(|error| error.to_string())?;
    let mut transfer = lock_transfer(&transfer);
    if transfer.sender.is_some() {
        return Err("a transfer is already under way".to_owned());
    }
    let size = data.len();
    transfer.sender = Some(XmodemSender::new(data, Instant::now()));
    Ok(size)
}

/// Abandons the upload under way, if there is one.
#[tauri::command]
pub fn xmodem_cancel(sessions: State<'_, Sessions>, id: u32) {
    if let Some(entry) = sessions.lock().get(&id) {
        lock_transfer(&entry.transfer).cancel_requested = true;
    }
}
