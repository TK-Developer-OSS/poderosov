//! An SSH server to test against, running inside the test process.
//!
//! It stands in for a shell on a pty: greets with the terminal size it was
//! given, echoes input, reports window changes, floods on Ctrl-F, receives an
//! XMODEM upload on Ctrl-R and logs out on Ctrl-D.
//! The keys under `tests/fixtures` are throwaways made for these tests.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{self, PublicKey};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Pty};
use tokio::net::TcpListener;

pub const USER: &str = "tester";
pub const PASSWORD: &str = "correct horse";
/// Passphrase of the `user_rsa` fixture, the key [`USER`] may log in with.
pub const KEY_PASSPHRASE: &str = "poderosov-test";

/// Logs out.
pub const CTRL_D: u8 = 0x04;
/// Makes the server send [`flood`], as `cat` on a big file would.
pub const CTRL_F: u8 = 0x06;
/// Makes the server wait for an XMODEM upload, as `rx` would.
pub const CTRL_R: u8 = 0x12;

/// A few megabytes of numbered lines: more than every buffer between the
/// server and the test put together.
pub fn flood() -> Vec<u8> {
    (0..400_000)
        .flat_map(|line| format!("{line:07}\r\n").into_bytes())
        .collect()
}

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

pub fn public_key(name: &str) -> PublicKey {
    let text = std::fs::read_to_string(fixture(name)).expect("public key fixture");
    PublicKey::from_openssh(text.trim()).expect("public key fixture")
}

/// Starts the server on a free local port. Its host key is the `host_rsa` fixture.
pub async fn start() -> SocketAddr {
    start_on(0).await
}

/// Starts the server on the given local port, or on a free one for port 0.
pub async fn start_on(port: u16) -> SocketAddr {
    let host_key = keys::load_secret_key(fixture("host_rsa"), None).expect("host key fixture");
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        // a real server stalls failed logins; the tests have no use for that
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
    let address = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        let mut server = TestServer;
        let _ = server.run_on_socket(config, &listener).await;
    });
    address
}

struct TestServer;

impl server::Server for TestServer {
    type Handler = FakeShell;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> FakeShell {
        FakeShell { size: (0, 0), receiving: None }
    }
}

struct FakeShell {
    size: (u32, u32),
    receiving: Option<XmodemReceiver>,
}

/// The receiving end of XMODEM with CRC, like `rx`: checks each block,
/// acknowledges it and, after EOT, reports what arrived.
#[derive(Default)]
struct XmodemReceiver {
    pending: Vec<u8>,
    file: Vec<u8>,
    next_block: u8,
}

impl XmodemReceiver {
    /// Handles input; `reply` sends to the client. Returns the report once the file is complete.
    fn feed(
        &mut self,
        input: &[u8],
        mut reply: impl FnMut(&[u8]) -> Result<(), russh::Error>,
    ) -> Result<Option<String>, russh::Error> {
        const BLOCK: usize = 3 + 128 + 2;
        if self.next_block == 0 {
            self.next_block = 1;
        }
        self.pending.extend_from_slice(input);
        loop {
            match self.pending.first() {
                Some(0x04) => {
                    reply(&[0x06])?;
                    return Ok(Some(format!(
                        "\r\nrx: received {} bytes, sum {}\r\n$ ",
                        self.file.len(),
                        checksum(&self.file)
                    )));
                }
                Some(0x01) if self.pending.len() >= BLOCK => {
                    let block: Vec<u8> = self.pending.drain(..BLOCK).collect();
                    let payload = &block[3..131];
                    let good = block[1] == self.next_block
                        && block[2] == 255 - self.next_block
                        && block[131..] == crc16(payload).to_be_bytes();
                    if good {
                        self.file.extend_from_slice(payload);
                        self.next_block = self.next_block.wrapping_add(1);
                        reply(&[0x06])?;
                    } else {
                        reply(&[0x15])?;
                    }
                }
                Some(0x01) | None => return Ok(None),
                Some(_) => {
                    self.pending.remove(0);
                }
            }
        }
    }
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// What the receiver reports, so that a test can check the file arrived intact.
pub fn checksum(data: &[u8]) -> u64 {
    data.iter().map(|&byte| u64::from(byte)).sum()
}

/// A failed login that, as with OpenSSH, leaves both methods open for another try.
fn rejected() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(MethodSet::from(
            &[MethodKind::PublicKey, MethodKind::Password][..],
        )),
        partial_success: false,
    }
}

impl server::Handler for FakeShell {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == USER && password == PASSWORD {
            Ok(Auth::Accept)
        } else {
            Ok(rejected())
        }
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        if user == USER && key.key_data() == public_key("user_rsa.pub").key_data() {
            Ok(Auth::Accept)
        } else {
            Ok(rejected())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.size = (cols, rows);
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let (cols, rows) = self.size;
        session.data(channel, format!("welcome {cols}x{rows}\r\n$ ").into_bytes())?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, format!("resized {cols}x{rows}\r\n").into_bytes())?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(receiver) = self.receiving.as_mut() {
            if let Some(report) = receiver.feed(data, |reply| session.data(channel, reply.to_vec()))? {
                self.receiving = None;
                session.data(channel, report.into_bytes())?;
            }
        } else if data == [CTRL_R] {
            self.receiving = Some(XmodemReceiver::default());
            session.data(channel, b"rx: waiting\r\nC".to_vec())?;
        } else if data == [CTRL_D] {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        } else if data == [CTRL_F] {
            session.data(channel, flood())?;
        } else {
            session.data(channel, data.to_vec())?;
        }
        Ok(())
    }
}
