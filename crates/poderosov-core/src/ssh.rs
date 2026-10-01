//! Interactive SSH2 sessions.

use std::borrow::Cow;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use russh::client::{self, AuthResult, DisconnectReason, Handle, Msg};
use russh::keys::{self, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Disconnect, SshId};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::known_hosts::{HostKeyStatus, KnownHosts};
use crate::session::{CloseReason, SessionCommand, SessionEvent, SessionHandle, TerminalSize};

/// How long to wait for the TCP connection before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The identification string the server sees.
const CLIENT_ID: &str = concat!("SSH-2.0-PoderosoV_", env!("CARGO_PKG_VERSION"));

/// Everything needed to open a session.
pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuth,
    /// The `TERM` the remote side is told about, e.g. `xterm`.
    pub term: String,
    pub size: TerminalSize,
}

/// How the user proves who they are.
pub enum SshAuth {
    Password(String),
    PublicKey {
        /// OpenSSH, PEM or PuTTY private key file.
        key_path: PathBuf,
        /// `None` for a key that is not encrypted.
        passphrase: Option<String>,
    },
}

/// A host key the user has to decide about.
#[derive(Debug, Clone)]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    /// Key type as SSH names it, e.g. `ssh-rsa`.
    pub algorithm: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    /// [`HostKeyStatus::Unknown`] for a host not seen before,
    /// [`HostKeyStatus::Changed`] if the key differs from the one on record.
    pub status: HostKeyStatus,
}

/// Asks the user whether a host key that is not on record should be trusted.
pub trait HostKeyPrompter: Send + 'static {
    /// `true` continues the connection and puts the key on record.
    fn confirm(&mut self, prompt: HostKeyPrompt) -> impl Future<Output = bool> + Send;
}

/// Why a session could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("could not connect to {host}:{port}: {source}")]
    Connect {
        host: String,
        port: u16,
        source: std::io::Error,
    },
    #[error("timed out connecting to {host}:{port}")]
    ConnectTimeout { host: String, port: u16 },
    #[error("the host key was not accepted")]
    HostKeyRejected,
    #[error("could not access the list of known hosts: {0}")]
    KnownHosts(#[source] std::io::Error),
    #[error("could not load the private key: {0}")]
    PrivateKey(#[source] keys::Error),
    /// `methods` are the authentication methods the server would still accept.
    #[error("authentication failed")]
    AuthFailed { methods: Vec<String> },
    #[error("the server refused to allocate a terminal")]
    PtyRefused,
    #[error(transparent)]
    Protocol(#[from] russh::Error),
}

/// Connects, logs in and starts a shell on a pseudo-terminal.
///
/// Output and the end of the session are reported through `events`. The
/// session reads from the server only as fast as `events` is drained, so a
/// bounded channel is what keeps a flood of output from piling up in memory.
pub async fn connect<P: HostKeyPrompter>(
    params: SshParams,
    known_hosts: KnownHosts,
    prompter: P,
    events: mpsc::Sender<SessionEvent>,
) -> Result<SessionHandle, SshError> {
    let SshParams { host, port, user, auth, term, size } = params;

    // Read the key before touching the network: a wrong path or passphrase
    // should not cost a connection attempt.
    let credentials = match auth {
        SshAuth::Password(password) => Credentials::Password(password),
        SshAuth::PublicKey { key_path, passphrase } => {
            let key = keys::load_secret_key(&key_path, passphrase.as_deref())
                .map_err(SshError::PrivateKey)?;
            Credentials::Key(Arc::new(key))
        }
    };

    let connecting = TcpStream::connect((host.as_str(), port));
    let socket = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Ok(Ok(socket)) => socket,
        Ok(Err(source)) => return Err(SshError::Connect { host, port, source }),
        Err(_) => return Err(SshError::ConnectTimeout { host, port }),
    };
    // Keystrokes are tiny packets that must not sit waiting for more data.
    let _ = socket.set_nodelay(true);

    let config = Arc::new(client::Config {
        client_id: SshId::Standard(Cow::Borrowed(CLIENT_ID)),
        ..Default::default()
    });
    let server_disconnect = ServerDisconnect::default();
    let handler = ClientHandler {
        host,
        port,
        known_hosts,
        prompter,
        server_disconnect: server_disconnect.clone(),
    };
    let mut session = client::connect_stream(config, socket, handler).await?;

    authenticate(&mut session, &user, credentials).await?;

    let mut channel = session.channel_open_session().await?;
    channel
        .request_pty(true, &term, size.cols, size.rows, 0, 0, &[])
        .await?;
    pty_granted(&mut channel).await?;
    channel.request_shell(true).await?;

    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let (reader, writer) = channel.split();
    tokio::spawn(run_session(
        session,
        reader,
        writer,
        commands_rx,
        events,
        server_disconnect,
    ));
    Ok(SessionHandle::new(commands_tx))
}

enum Credentials {
    Password(String),
    Key(Arc<PrivateKey>),
}

/// What the server said when it ended the connection itself.
#[derive(Clone, Default)]
struct ServerDisconnect(Arc<Mutex<Option<ServerDisconnectInfo>>>);

struct ServerDisconnectInfo {
    /// The server gave "by application" as the reason: an ordinary goodbye.
    orderly: bool,
    message: String,
}

impl ServerDisconnect {
    fn set(&self, info: ServerDisconnectInfo) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(info);
        }
    }

    fn take(&self) -> Option<ServerDisconnectInfo> {
        self.0.lock().ok()?.take()
    }
}

struct ClientHandler<P> {
    host: String,
    port: u16,
    known_hosts: KnownHosts,
    prompter: P,
    server_disconnect: ServerDisconnect,
}

impl<P: HostKeyPrompter> client::Handler for ClientHandler<P> {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, SshError> {
        let key = server_key.public_key();
        let status = self
            .known_hosts
            .check(&self.host, self.port, &key)
            .map_err(SshError::KnownHosts)?;
        if status == HostKeyStatus::Known {
            return Ok(true);
        }

        let prompt = HostKeyPrompt {
            host: self.host.clone(),
            port: self.port,
            algorithm: key.algorithm().as_str().to_owned(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            status,
        };
        if !self.prompter.confirm(prompt).await {
            return Err(SshError::HostKeyRejected);
        }
        self.known_hosts
            .remember(&self.host, self.port, &key)
            .map_err(SshError::KnownHosts)?;
        Ok(true)
    }

    async fn disconnected(&mut self, reason: DisconnectReason<SshError>) -> Result<(), SshError> {
        match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                self.server_disconnect.set(ServerDisconnectInfo {
                    orderly: matches!(info.reason_code, Disconnect::ByApplication),
                    message: info.message,
                });
                Ok(())
            }
            DisconnectReason::Error(error) => Err(error),
        }
    }
}

async fn authenticate<H: client::Handler>(
    session: &mut Handle<H>,
    user: &str,
    credentials: Credentials,
) -> Result<(), SshError> {
    let result = match credentials {
        Credentials::Password(password) => session.authenticate_password(user, password).await?,
        Credentials::Key(key) => authenticate_with_key(session, user, key).await?,
    };
    match result {
        AuthResult::Success => Ok(()),
        AuthResult::Failure { remaining_methods, .. } => Err(SshError::AuthFailed {
            methods: remaining_methods.iter().map(String::from).collect(),
        }),
    }
}

async fn authenticate_with_key<H: client::Handler>(
    session: &mut Handle<H>,
    user: &str,
    key: Arc<PrivateKey>,
) -> Result<AuthResult, russh::Error> {
    if !key.algorithm().is_rsa() {
        let key = PrivateKeyWithHashAlg::new(key, None);
        return session.authenticate_publickey(user, key).await;
    }

    // An RSA key can sign with SHA-2 or, for servers that predate that, with
    // SHA-1 (plain `ssh-rsa`). Most servers say which they take.
    match session.best_supported_rsa_hash().await? {
        Some(hash) => {
            let key = PrivateKeyWithHashAlg::new(key, hash);
            session.authenticate_publickey(user, key).await
        }
        // This one does not: try SHA-2, which current servers insist on,
        // then the SHA-1 signature a server too old to say will expect.
        None => {
            let sha2 = PrivateKeyWithHashAlg::new(key.clone(), Some(HashAlg::Sha256));
            let result = session.authenticate_publickey(user, sha2).await?;
            if result.success() {
                return Ok(result);
            }
            let sha1 = PrivateKeyWithHashAlg::new(key, None);
            session.authenticate_publickey(user, sha1).await
        }
    }
}

/// Waits for the answer to the pty request. Nothing else can arrive on the
/// channel before a shell has been asked for.
async fn pty_granted(channel: &mut Channel<Msg>) -> Result<(), SshError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => return Err(SshError::PtyRefused),
            Some(_) => {}
            None => return Err(russh::Error::Disconnect.into()),
        }
    }
}

/// Moves data between the channel and the front end until the session ends.
async fn run_session<H>(
    mut session: Handle<H>,
    mut reader: ChannelReadHalf,
    writer: ChannelWriteHalf<Msg>,
    commands: mpsc::UnboundedReceiver<SessionCommand>,
    events: mpsc::Sender<SessionEvent>,
    server_disconnect: ServerDisconnect,
) where
    H: client::Handler,
    H::Error: std::fmt::Display,
{
    // Input goes out from a task of its own. Sending blocks while the server's
    // receive window is full, and the window only reopens if incoming data
    // keeps being read in the meantime.
    let mut writing = tokio::spawn(write_input(writer, commands));

    let mut exit_status = None;
    // Output read from the channel that `events` had no room for yet. Nothing
    // more is read until it has been handed over.
    let mut pending: Option<Bytes> = None;

    let reason = loop {
        tokio::select! {
            message = reader.wait(), if pending.is_none() => match message {
                // stderr of a shell on a pty is rare, but belongs on screen too
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    pending = Some(data);
                }
                Some(ChannelMsg::ExitStatus { exit_status: status }) => exit_status = Some(status),
                // the only request still awaiting an answer is the one for a shell
                Some(ChannelMsg::Failure) => {
                    break CloseReason::Error("the server refused to start a shell".to_owned());
                }
                Some(ChannelMsg::Close) => break CloseReason::Exited(exit_status),
                Some(_) => {}
                None => break connection_lost(&mut session, &server_disconnect, exit_status).await,
            },
            permit = events.reserve(), if pending.is_some() => match permit {
                Ok(permit) => {
                    if let Some(data) = pending.take() {
                        permit.send(SessionEvent::Data(data));
                    }
                }
                // nobody is displaying the session any more
                Err(_) => break CloseReason::ClosedByUser,
            },
            finished = &mut writing => break match finished {
                Ok(Ok(())) => CloseReason::ClosedByUser,
                Ok(Err(error)) => CloseReason::Error(error.to_string()),
                Err(error) => CloseReason::Error(error.to_string()),
            },
        }
    };

    writing.abort();
    // Dropped first so that a transport stuck handing us output can take the disconnect.
    drop(reader);
    let _ = session.disconnect(Disconnect::ByApplication, "", "en").await;
    let _ = events.send(SessionEvent::Closed(reason)).await;
}

/// Sends what the front end asks for, in order, until it asks to close.
async fn write_input(
    writer: ChannelWriteHalf<Msg>,
    mut commands: mpsc::UnboundedReceiver<SessionCommand>,
) -> Result<(), russh::Error> {
    while let Some(command) = commands.recv().await {
        match command {
            SessionCommand::Write(data) => writer.data_bytes(data).await?,
            SessionCommand::Resize(size) => {
                writer.window_change(size.cols, size.rows, 0, 0).await?
            }
            SessionCommand::Close => break,
        }
    }
    Ok(())
}

/// The channel ended without being closed, so the whole connection is gone.
/// Finds out why from the transport.
async fn connection_lost<H>(
    session: &mut Handle<H>,
    server_disconnect: &ServerDisconnect,
    exit_status: Option<u32>,
) -> CloseReason
where
    H: client::Handler,
    H::Error: std::fmt::Display,
{
    // The transport task is finishing; its result is the error that ended it.
    let transport = tokio::time::timeout(Duration::from_secs(1), session).await;
    if let Ok(Err(error)) = transport {
        return CloseReason::Error(error.to_string());
    }
    match server_disconnect.take() {
        Some(info) if !info.orderly => CloseReason::Error(if info.message.is_empty() {
            "disconnected by the server".to_owned()
        } else {
            format!("disconnected by the server: {}", info.message)
        }),
        _ => CloseReason::Exited(exit_status),
    }
}
