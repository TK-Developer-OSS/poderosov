//! Session and protocol layer of PoderosoV.
//!
//! Nothing in here knows about the GUI. A front end opens a session, drives it
//! through a [`session::SessionHandle`] and renders the
//! [`session::SessionEvent`]s it produces.

pub mod known_hosts;
pub mod session;
pub mod ssh;
