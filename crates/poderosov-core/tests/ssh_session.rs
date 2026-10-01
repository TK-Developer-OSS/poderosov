//! SSH sessions end to end, against the server in `common`.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use poderosov_core::known_hosts::{HostKeyStatus, KnownHosts};
use poderosov_core::session::{CloseReason, SessionEvent, SessionHandle, TerminalSize};
use poderosov_core::ssh::{self, HostKeyPrompt, HostKeyPrompter, SshAuth, SshError, SshParams};
use tokio::sync::mpsc;

use common::{KEY_PASSPHRASE, PASSWORD, USER};

/// Gives every host key prompt the same answer and keeps what was asked.
#[derive(Clone)]
struct Answer {
    accept: bool,
    asked: Arc<Mutex<Vec<HostKeyPrompt>>>,
}

impl Answer {
    fn new(accept: bool) -> Self {
        Self { accept, asked: Arc::default() }
    }

    fn asked(&self) -> Vec<HostKeyPrompt> {
        self.asked.lock().unwrap().clone()
    }
}

impl HostKeyPrompter for Answer {
    async fn confirm(&mut self, prompt: HostKeyPrompt) -> bool {
        self.asked.lock().unwrap().push(prompt);
        self.accept
    }
}

/// A running test server and an empty list of known hosts.
struct Fixture {
    address: SocketAddr,
    known_hosts: KnownHosts,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        Self {
            address: common::start().await,
            known_hosts: KnownHosts::new(dir.path().join("ssh_known_hosts")),
            _dir: dir,
        }
    }

    async fn connect(
        &self,
        auth: SshAuth,
        answer: &Answer,
    ) -> Result<(SessionHandle, mpsc::Receiver<SessionEvent>), SshError> {
        let params = SshParams {
            host: "127.0.0.1".to_owned(),
            port: self.address.port(),
            user: USER.to_owned(),
            auth,
            term: "xterm".to_owned(),
            size: TerminalSize { cols: 80, rows: 24 },
        };
        let (events_tx, events) = mpsc::channel(8);
        let session =
            ssh::connect(params, self.known_hosts.clone(), answer.clone(), events_tx).await?;
        Ok((session, events))
    }
}

fn password() -> SshAuth {
    SshAuth::Password(PASSWORD.to_owned())
}

/// Collects output until it contains `expected`.
async fn read_until(events: &mut mpsc::Receiver<SessionEvent>, expected: &str) -> String {
    let mut output = String::new();
    while !output.contains(expected) {
        let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .unwrap_or_else(|_| panic!("no {expected:?} within 10 s, only {output:?}"));
        match event {
            Some(SessionEvent::Data(data)) => output.push_str(&String::from_utf8_lossy(&data)),
            other => panic!("waiting for {expected:?} but got {other:?} after {output:?}"),
        }
    }
    output
}

/// Skips any remaining output and returns why the session ended.
async fn closed(events: &mut mpsc::Receiver<SessionEvent>) -> CloseReason {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("the session did not end within 10 s");
        match event {
            Some(SessionEvent::Data(_)) => {}
            Some(SessionEvent::Closed(reason)) => return reason,
            None => panic!("the event channel closed without a Closed event"),
        }
    }
}

#[tokio::test]
async fn password_login_gives_an_interactive_terminal() {
    let fixture = Fixture::new().await;
    let (session, mut events) = fixture
        .connect(password(), &Answer::new(true))
        .await
        .expect("login");

    // the pty was requested with the size passed to connect
    read_until(&mut events, "welcome 80x24\r\n$ ").await;

    session.write(b"ls -l\r".to_vec()).unwrap();
    read_until(&mut events, "ls -l\r").await;

    session.resize(TerminalSize { cols: 132, rows: 43 }).unwrap();
    read_until(&mut events, "resized 132x43").await;

    session.write(vec![common::CTRL_D]).unwrap();
    assert_eq!(closed(&mut events).await, CloseReason::Exited(Some(0)));
}

#[tokio::test]
async fn a_wrong_password_is_an_authentication_failure() {
    let fixture = Fixture::new().await;
    let result = fixture
        .connect(SshAuth::Password("wrong".to_owned()), &Answer::new(true))
        .await;

    match result {
        // the methods the server said it would still take
        Err(SshError::AuthFailed { methods }) => assert_eq!(methods, ["publickey", "password"]),
        Err(other) => panic!("expected AuthFailed, got {other:?}"),
        Ok(_) => panic!("logged in with a wrong password"),
    }
}

#[tokio::test]
async fn rsa_key_login_with_a_passphrase() {
    let fixture = Fixture::new().await;
    let auth = SshAuth::PublicKey {
        key_path: common::fixture("user_rsa"),
        passphrase: Some(KEY_PASSPHRASE.to_owned()),
    };
    let (_session, mut events) = fixture
        .connect(auth, &Answer::new(true))
        .await
        .expect("login");

    read_until(&mut events, "welcome 80x24").await;
}

#[tokio::test]
async fn a_wrong_key_passphrase_fails_before_connecting() {
    let fixture = Fixture::new().await;
    let answer = Answer::new(true);
    let auth = SshAuth::PublicKey {
        key_path: common::fixture("user_rsa"),
        passphrase: Some("wrong".to_owned()),
    };
    let result = fixture.connect(auth, &answer).await;

    assert!(matches!(result, Err(SshError::PrivateKey(_))), "{:?}", result.err());
    assert!(answer.asked().is_empty(), "the server was contacted");
}

#[tokio::test]
async fn an_unknown_host_key_is_put_to_the_user_once() {
    let fixture = Fixture::new().await;
    let answer = Answer::new(true);

    fixture.connect(password(), &answer).await.expect("first login");
    fixture.connect(password(), &answer).await.expect("second login");

    let asked = answer.asked();
    assert_eq!(asked.len(), 1, "the accepted key was not remembered");
    assert_eq!(asked[0].status, HostKeyStatus::Unknown);
    assert_eq!(asked[0].host, "127.0.0.1");
    assert_eq!(asked[0].port, fixture.address.port());
    assert_eq!(asked[0].algorithm, "ssh-rsa");
    let expected = common::public_key("host_rsa.pub")
        .fingerprint(russh::keys::HashAlg::Sha256)
        .to_string();
    assert_eq!(asked[0].fingerprint, expected);
}

#[tokio::test]
async fn refusing_a_host_key_aborts_and_remembers_nothing() {
    let fixture = Fixture::new().await;
    let refuse = Answer::new(false);

    let result = fixture.connect(password(), &refuse).await;
    assert!(matches!(result, Err(SshError::HostKeyRejected)), "{:?}", result.err());

    let result = fixture.connect(password(), &refuse).await;
    assert!(matches!(result, Err(SshError::HostKeyRejected)), "{:?}", result.err());
    assert_eq!(refuse.asked().len(), 2, "a refused key must be asked about again");
}

#[tokio::test]
async fn a_changed_host_key_is_reported_as_changed() {
    let fixture = Fixture::new().await;
    // some other RSA key is on record for this server
    fixture
        .known_hosts
        .remember("127.0.0.1", fixture.address.port(), &common::public_key("user_rsa.pub"))
        .unwrap();
    let answer = Answer::new(true);

    fixture.connect(password(), &answer).await.expect("login");
    assert_eq!(answer.asked()[0].status, HostKeyStatus::Changed);

    // accepting replaced the key on record
    fixture.connect(password(), &answer).await.expect("second login");
    assert_eq!(answer.asked().len(), 1);
}

#[tokio::test]
async fn closing_the_handle_ends_the_session() {
    let fixture = Fixture::new().await;
    let (session, mut events) = fixture
        .connect(password(), &Answer::new(true))
        .await
        .expect("login");
    read_until(&mut events, "$ ").await;

    session.close();
    assert_eq!(closed(&mut events).await, CloseReason::ClosedByUser);
}

#[tokio::test]
async fn a_flood_of_output_waits_for_a_slow_reader_and_arrives_intact() {
    let fixture = Fixture::new().await;
    let (session, mut events) = fixture
        .connect(password(), &Answer::new(true))
        .await
        .expect("login");
    read_until(&mut events, "$ ").await;

    session.write(vec![common::CTRL_F]).unwrap();
    // Give the flood time to back up against the full event queue.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let expected = common::flood();
    let mut received = Vec::with_capacity(expected.len());
    while received.len() < expected.len() {
        let event = tokio::time::timeout(Duration::from_secs(30), events.recv())
            .await
            .expect("the output stalled");
        match event {
            Some(SessionEvent::Data(data)) => received.extend_from_slice(&data),
            other => panic!("expected output, got {other:?} after {} bytes", received.len()),
        }
    }
    assert!(received == expected, "the output arrived damaged or out of order");

    // the session is still usable afterwards
    session.write(b"ok\r".to_vec()).unwrap();
    read_until(&mut events, "ok\r").await;
}

#[tokio::test]
async fn an_xmodem_upload_arrives_intact() {
    use poderosov_core::xmodem::{BLOCK_SIZE, Step, XmodemSender};
    use std::time::Instant;

    let fixture = Fixture::new().await;
    let (session, mut events) = fixture
        .connect(password(), &Answer::new(true))
        .await
        .expect("login");
    read_until(&mut events, "$ ").await;

    let file: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let mut sender = XmodemSender::new(file.clone(), Instant::now());
    session.write(vec![common::CTRL_R]).unwrap();

    // Plays the part the application has: server output goes to the sender,
    // what the sender asks for goes back to the server.
    let mut finished = false;
    while !finished {
        let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("the transfer stalled");
        let Some(SessionEvent::Data(data)) = event else {
            panic!("expected output, got {event:?}");
        };
        for step in sender.receive(&data, Instant::now()) {
            match step {
                Step::Send(bytes) => session.write(bytes).unwrap(),
                Step::Progress { .. } => {}
                Step::Finished => finished = true,
                Step::Failed(reason) => panic!("transfer failed: {reason}"),
            }
        }
    }

    // the receiver sees the file padded out to whole blocks
    let mut padded = file.clone();
    padded.resize(file.len().div_ceil(BLOCK_SIZE) * BLOCK_SIZE, 0x1a);
    let report = format!("received {} bytes, sum {}", padded.len(), common::checksum(&padded));
    read_until(&mut events, &report).await;
}
