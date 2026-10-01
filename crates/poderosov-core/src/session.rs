//! What every kind of terminal session looks like from the outside,
//! whichever protocol carries it.

use bytes::Bytes;
use tokio::sync::mpsc;

/// Size of a terminal in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub cols: u32,
    pub rows: u32,
}

/// What a running session reports to whoever is displaying it.
#[derive(Debug)]
pub enum SessionEvent {
    /// Bytes from the remote side, to be fed to the terminal emulator as they are.
    Data(Bytes),
    /// The session is over. Nothing follows this event.
    Closed(CloseReason),
}

/// Why a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// The remote side ended the session in an orderly way, e.g. the shell
    /// exited. Carries the exit status if one was reported.
    Exited(Option<u32>),
    /// Closed from this side, through [`SessionHandle::close`] or by dropping
    /// every handle.
    ClosedByUser,
    /// The connection failed or was cut.
    Error(String),
}

pub(crate) enum SessionCommand {
    Write(Vec<u8>),
    Resize(TerminalSize),
    Close,
}

/// The session a [`SessionHandle`] referred to has already ended.
#[derive(Debug, thiserror::Error)]
#[error("the session is closed")]
pub struct SessionClosed;

/// Drives a running session. Dropping every clone closes the session.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    commands: mpsc::UnboundedSender<SessionCommand>,
}

impl SessionHandle {
    pub(crate) fn new(commands: mpsc::UnboundedSender<SessionCommand>) -> Self {
        Self { commands }
    }

    /// Sends typed or pasted input to the remote side.
    pub fn write(&self, data: Vec<u8>) -> Result<(), SessionClosed> {
        self.send(SessionCommand::Write(data))
    }

    /// Tells the remote side that the terminal now has this size.
    pub fn resize(&self, size: TerminalSize) -> Result<(), SessionClosed> {
        self.send(SessionCommand::Resize(size))
    }

    /// Ends the session. Does nothing if it has already ended.
    pub fn close(&self) {
        let _ = self.send(SessionCommand::Close);
    }

    fn send(&self, command: SessionCommand) -> Result<(), SessionClosed> {
        self.commands.send(command).map_err(|_| SessionClosed)
    }
}
