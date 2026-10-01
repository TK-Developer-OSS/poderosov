//! The server the integration tests talk to, on a fixed local port, for
//! trying the GUI without a real SSH server at hand.
//!
//! ```sh
//! cargo run -p poderosov-core --example test_sshd
//! ```
//!
//! Then connect to 127.0.0.1 port 2222 as `tester`, password `correct horse`,
//! or with the key `tests/fixtures/user_rsa`, passphrase `poderosov-test`.
//! It echoes what is typed, floods on Ctrl-F and logs out on Ctrl-D.

#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

const PORT: u16 = 2222;

#[tokio::main]
async fn main() {
    let address = common::start_on(PORT).await;
    println!("test SSH server listening on {address}; stop it with Ctrl-C");
    std::future::pending::<()>().await;
}
