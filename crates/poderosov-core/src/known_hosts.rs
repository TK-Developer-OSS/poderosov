//! The host keys the user has chosen to trust.
//!
//! The file uses the OpenSSH layout, one `host algorithm key` line per key
//! with `[host]:port` for anything but port 22, but it is PoderosoV's own:
//! `~/.ssh/known_hosts` is neither read nor written.

use std::fs;
use std::io;
use std::path::PathBuf;

use russh::keys::PublicKey;

/// How a key presented by a server relates to what is on record for that host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyStatus {
    /// It is the key on record.
    Known,
    /// No key of this type is on record for the host.
    Unknown,
    /// A different key of the same type is on record: the server was
    /// reinstalled, or something is impersonating it.
    Changed,
}

/// The trusted host keys kept in one file.
#[derive(Debug, Clone)]
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    /// A store kept in the file at `path`, which does not have to exist yet.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Compares `key` with what is on record for `host`.
    pub fn check(&self, host: &str, port: u16, key: &PublicKey) -> io::Result<HostKeyStatus> {
        let name = entry_name(host, port);
        let mut status = HostKeyStatus::Unknown;
        for line in self.read()?.lines() {
            let Some(recorded) = parse_entry(line, &name) else {
                continue;
            };
            if recorded.key_data() == key.key_data() {
                return Ok(HostKeyStatus::Known);
            }
            if recorded.algorithm() == key.algorithm() {
                status = HostKeyStatus::Changed;
            }
        }
        Ok(status)
    }

    /// Records `key` as the key of `host`, replacing any key of the same type
    /// recorded for it before.
    pub fn remember(&self, host: &str, port: u16, key: &PublicKey) -> io::Result<()> {
        let name = entry_name(host, port);
        let mut contents = String::new();
        for line in self.read()?.lines() {
            let superseded = parse_entry(line, &name)
                .is_some_and(|recorded| recorded.algorithm() == key.algorithm());
            if !superseded {
                contents.push_str(line);
                contents.push('\n');
            }
        }
        let encoded = key
            .to_openssh()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        contents.push_str(&format!("{name} {}\n", encoded.trim_end()));

        if let Some(directory) = self.path.parent() {
            fs::create_dir_all(directory)?;
        }
        fs::write(&self.path, contents)
    }

    fn read(&self) -> io::Result<String> {
        match fs::read_to_string(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            result => result,
        }
    }
}

/// The name a host is filed under: the bare host for port 22, `[host]:port`
/// for any other port.
fn entry_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 {
        host
    } else {
        format!("[{host}]:{port}")
    }
}

/// The key on `line`, if the line is an entry for `name`. Comments, entries
/// for other hosts and lines that do not parse give `None`.
fn parse_entry(line: &str, name: &str) -> Option<PublicKey> {
    let (host, key) = line.trim().split_once(char::is_whitespace)?;
    if host != name {
        return None;
    }
    PublicKey::from_openssh(key.trim_start()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_A: &str = include_str!("../tests/fixtures/host_rsa.pub");
    const RSA_B: &str = include_str!("../tests/fixtures/user_rsa.pub");
    const ED25519: &str = include_str!("../tests/fixtures/other_ed25519.pub");

    fn key(text: &str) -> PublicKey {
        PublicKey::from_openssh(text.trim()).expect("fixture is a public key")
    }

    /// A store in a directory that does not exist yet, as on first launch.
    fn store() -> (tempfile::TempDir, KnownHosts) {
        let dir = tempfile::tempdir().expect("temp dir");
        let hosts = KnownHosts::new(dir.path().join("config").join("ssh_known_hosts"));
        (dir, hosts)
    }

    #[test]
    fn a_host_is_unknown_until_its_key_is_remembered() {
        let (_dir, hosts) = store();
        let key = key(RSA_A);

        assert_eq!(hosts.check("example.com", 22, &key).unwrap(), HostKeyStatus::Unknown);
        hosts.remember("example.com", 22, &key).unwrap();
        assert_eq!(hosts.check("example.com", 22, &key).unwrap(), HostKeyStatus::Known);
        assert_eq!(hosts.check("EXAMPLE.com", 22, &key).unwrap(), HostKeyStatus::Known);
        assert_eq!(hosts.check("other.example.com", 22, &key).unwrap(), HostKeyStatus::Unknown);
    }

    #[test]
    fn a_different_key_of_the_same_type_is_a_change() {
        let (_dir, hosts) = store();
        hosts.remember("example.com", 22, &key(RSA_A)).unwrap();

        assert_eq!(hosts.check("example.com", 22, &key(RSA_B)).unwrap(), HostKeyStatus::Changed);
        assert_eq!(hosts.check("example.com", 22, &key(ED25519)).unwrap(), HostKeyStatus::Unknown);
    }

    #[test]
    fn remembering_replaces_only_the_same_type_of_key_of_the_same_host() {
        let (_dir, hosts) = store();
        hosts.remember("example.com", 22, &key(RSA_A)).unwrap();
        hosts.remember("example.com", 22, &key(ED25519)).unwrap();
        hosts.remember("other.example.com", 22, &key(RSA_A)).unwrap();

        hosts.remember("example.com", 22, &key(RSA_B)).unwrap();

        assert_eq!(hosts.check("example.com", 22, &key(RSA_B)).unwrap(), HostKeyStatus::Known);
        assert_eq!(hosts.check("example.com", 22, &key(RSA_A)).unwrap(), HostKeyStatus::Changed);
        assert_eq!(hosts.check("example.com", 22, &key(ED25519)).unwrap(), HostKeyStatus::Known);
        assert_eq!(hosts.check("other.example.com", 22, &key(RSA_A)).unwrap(), HostKeyStatus::Known);
    }

    #[test]
    fn the_same_host_on_another_port_is_a_separate_entry() {
        let (_dir, hosts) = store();
        hosts.remember("example.com", 2222, &key(RSA_A)).unwrap();

        assert_eq!(hosts.check("example.com", 2222, &key(RSA_A)).unwrap(), HostKeyStatus::Known);
        assert_eq!(hosts.check("example.com", 22, &key(RSA_A)).unwrap(), HostKeyStatus::Unknown);
    }
}
