//! Poderosa 4 terminal shortcut files (`*.gts`).
//!
//! A shortcut holds what is needed to open one connection. Poderosa 4 writes
//!
//! ```xml
//! <poderosa-shortcut version="4.0">
//!   <Poderosa.Terminal.TerminalSettings encoding="UTF8" caption="rocky9" />
//!   <Poderosa.Protocols.SSHLoginParameter destination="rocky9" account="me" />
//! </poderosa-shortcut>
//! ```
//!
//! in the system's ANSI code page (Shift_JIS on Japanese Windows), as the XML
//! declaration says. Older versions put everything in attributes of the root
//! element. Both are read; files are written in the 4.0 layout, as UTF-8.
//! Passwords that Poderosa may have stored in a shortcut are not read.

use std::collections::HashMap;

use encoding_rs::{Encoding, UTF_8};
use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

const SETTINGS_ELEMENT: &str = "Poderosa.Terminal.TerminalSettings";
const SSH_ELEMENT: &str = "Poderosa.Protocols.SSHLoginParameter";
const TELNET_ELEMENT: &str = "Poderosa.Protocols.TelnetParameter";

/// One connection as a shortcut file describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shortcut {
    /// What the tab is called; empty if the file does not say.
    pub caption: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    /// Private key file for [`Auth::PublicKey`]; empty otherwise.
    pub key_path: String,
    /// `TERM`, e.g. `xterm`.
    pub term: String,
    /// WHATWG label: `utf-8`, `euc-jp` or `shift_jis`. Encodings PoderosoV
    /// does not offer come back as `utf-8`.
    pub encoding: String,
    pub newline: NewLine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ssh2,
    /// Not supported by PoderosoV; reported so that the user can be told.
    Ssh1,
    /// Not supported yet.
    Telnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Password,
    PublicKey,
    KeyboardInteractive,
}

/// What the Enter key sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewLine {
    Cr,
    Lf,
    CrLf,
}

impl NewLine {
    fn parse(text: &str) -> Self {
        match text {
            "LF" => NewLine::Lf,
            "CRLF" => NewLine::CrLf,
            _ => NewLine::Cr,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            NewLine::Cr => "CR",
            NewLine::Lf => "LF",
            NewLine::CrLf => "CRLF",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GtsError {
    #[error("not a Poderosa shortcut file")]
    NotAShortcut,
    #[error("the file is not well-formed XML: {0}")]
    Xml(String),
}

/// Reads a shortcut file's contents.
pub fn parse(bytes: &[u8]) -> Result<Shortcut, GtsError> {
    let text = decode(bytes);
    let mut reader = Reader::from_str(&text);
    let mut root: Option<Element> = None;
    let mut children = Vec::new();
    let mut depth = 0usize;
    loop {
        let event = reader.read_event().map_err(|error| GtsError::Xml(error.to_string()))?;
        match event {
            Event::Start(start) => {
                record(&start, depth, &mut root, &mut children)?;
                depth += 1;
            }
            Event::Empty(start) => record(&start, depth, &mut root, &mut children)?,
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof => break,
            _ => {}
        }
    }

    let root = root.ok_or(GtsError::NotAShortcut)?;
    if root.name != "poderosa-shortcut" {
        return Err(GtsError::NotAShortcut);
    }
    if root.get("version") == Some("4.0") {
        from_version_4(&children)
    } else {
        from_old_format(&root)
    }
}

/// Writes a shortcut in the Poderosa 4.0 layout, readable by Poderosa itself.
pub fn write(shortcut: &Shortcut) -> String {
    let caption = if shortcut.caption.is_empty() { &shortcut.host } else { &shortcut.caption };
    let mut settings = vec![
        ("encoding", poderosa_encoding(&shortcut.encoding).to_owned()),
        ("caption", caption.clone()),
    ];
    if shortcut.newline != NewLine::Cr {
        settings.push(("transmit-nl", shortcut.newline.name().to_owned()));
    }

    let mut login = vec![("destination", shortcut.host.clone())];
    if shortcut.term != "xterm" {
        login.insert(0, ("terminal-type", shortcut.term.clone()));
    }
    if shortcut.port != 22 {
        login.push(("port", shortcut.port.to_string()));
    }
    match shortcut.auth {
        Auth::Password => {}
        Auth::PublicKey => login.push(("authentication", "PublicKey".to_owned())),
        Auth::KeyboardInteractive => {
            login.push(("authentication", "KeyboardInteractive".to_owned()))
        }
    }
    login.push(("account", shortcut.user.clone()));
    if !shortcut.key_path.is_empty() {
        login.push(("identityFileName", shortcut.key_path.clone()));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n\
         <poderosa-shortcut version=\"4.0\">\r\n  {}\r\n  {}\r\n</poderosa-shortcut>\r\n",
        empty_element(SETTINGS_ELEMENT, &settings),
        empty_element(SSH_ELEMENT, &login),
    )
}

struct Element {
    name: String,
    attributes: HashMap<String, String>,
}

impl Element {
    fn get(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }
}

fn record(
    start: &BytesStart<'_>,
    depth: usize,
    root: &mut Option<Element>,
    children: &mut Vec<Element>,
) -> Result<(), GtsError> {
    if depth > 1 {
        return Ok(());
    }
    let mut attributes = HashMap::new();
    for attribute in start.attributes() {
        let attribute = attribute.map_err(|error| GtsError::Xml(error.to_string()))?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|error| GtsError::Xml(error.to_string()))?;
        attributes.insert(attribute.key.as_ref().to_owned(), value.into_owned());
    }
    let element = Element { name: start.name().as_ref().to_owned(), attributes };
    if depth == 0 {
        *root = Some(element);
    } else {
        children.push(element);
    }
    Ok(())
}

fn from_version_4(children: &[Element]) -> Result<Shortcut, GtsError> {
    let settings = children.iter().find(|element| element.name == SETTINGS_ELEMENT);
    let (login, protocol) = children
        .iter()
        .find_map(|element| match element.name.as_str() {
            SSH_ELEMENT => Some((element, None)),
            TELNET_ELEMENT => Some((element, Some(Protocol::Telnet))),
            _ => None,
        })
        .ok_or(GtsError::NotAShortcut)?;
    let protocol = protocol.unwrap_or(match login.get("method") {
        Some("SSH1") => Protocol::Ssh1,
        _ => Protocol::Ssh2,
    });
    let default_port = if protocol == Protocol::Telnet { 23 } else { 22 };

    let setting = |name: &str| settings.and_then(|settings| settings.get(name));
    // The connection's own TERM wins; the settings only name a terminal kind.
    let term = login
        .get("terminal-type")
        .map(str::to_owned)
        .unwrap_or_else(|| term_from_kind(setting("terminal-type")));

    Ok(Shortcut {
        caption: setting("caption").unwrap_or_default().to_owned(),
        protocol,
        host: login.get("destination").unwrap_or_default().to_owned(),
        port: login.get("port").and_then(|port| port.parse().ok()).unwrap_or(default_port),
        user: login.get("account").unwrap_or_default().to_owned(),
        auth: parse_auth(login.get("authentication")),
        key_path: login.get("identityFileName").unwrap_or_default().to_owned(),
        term,
        encoding: whatwg_encoding(setting("encoding")).to_owned(),
        newline: NewLine::parse(setting("transmit-nl").unwrap_or_default()),
    })
}

/// Poderosa before 4.0: everything on the root element; an account means SSH.
fn from_old_format(root: &Element) -> Result<Shortcut, GtsError> {
    if root.get("type") != Some("tcp") {
        return Err(GtsError::NotAShortcut);
    }
    let user = root.get("account").unwrap_or_default().to_owned();
    let protocol = if user.is_empty() {
        Protocol::Telnet
    } else if root.get("method") == Some("SSH1") {
        Protocol::Ssh1
    } else {
        Protocol::Ssh2
    };
    let default_port = if protocol == Protocol::Telnet { 23 } else { 22 };
    Ok(Shortcut {
        caption: root.get("caption").unwrap_or_default().to_owned(),
        protocol,
        host: root.get("host").unwrap_or_default().to_owned(),
        port: root.get("port").and_then(|port| port.parse().ok()).unwrap_or(default_port),
        user,
        auth: parse_auth(root.get("auth")),
        key_path: root.get("keyfile").unwrap_or_default().to_owned(),
        term: term_from_kind(root.get("terminal-type")),
        encoding: whatwg_encoding(root.get("encoding")).to_owned(),
        newline: NewLine::parse(root.get("transmit-nl").unwrap_or_default()),
    })
}

fn parse_auth(text: Option<&str>) -> Auth {
    match text {
        Some("PublicKey") => Auth::PublicKey,
        Some("KeyboardInteractive") => Auth::KeyboardInteractive,
        _ => Auth::Password,
    }
}

/// `TERM` for Poderosa's terminal kinds.
fn term_from_kind(kind: Option<&str>) -> String {
    match kind {
        Some("VT100") => "vt100",
        Some("KTerm") => "kterm",
        Some("XTerm256Color") => "xterm-256color",
        _ => "xterm",
    }
    .to_owned()
}

/// Poderosa's encoding names, including the localized ones of old files.
fn whatwg_encoding(name: Option<&str>) -> &'static str {
    match name.unwrap_or_default().to_ascii_lowercase().as_str() {
        "euc_jp" | "euc-jp" | "euc-jp(jis)" => "euc-jp",
        "shift_jis" | "shift-jis" => "shift_jis",
        _ => "utf-8",
    }
}

fn poderosa_encoding(label: &str) -> &'static str {
    match label {
        "euc-jp" => "EUC_JP",
        "shift_jis" => "SHIFT_JIS",
        _ => "UTF8",
    }
}

/// The file's text, in the encoding its XML declaration names.
fn decode(bytes: &[u8]) -> String {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]);
    let declared = head
        .split_once("encoding=")
        .and_then(|(_, rest)| {
            let quote = rest.chars().next()?;
            rest[1..].split(quote).next()
        })
        .and_then(|label| Encoding::for_label(label.as_bytes()))
        .unwrap_or(UTF_8);
    let (text, _, _) = declared.decode(bytes);
    text.into_owned()
}

fn empty_element(name: &str, attributes: &[(&str, String)]) -> String {
    let mut element = format!("<{name}");
    for (key, value) in attributes {
        element.push_str(&format!(" {key}=\"{}\"", escape(value)));
    }
    element.push_str(" />");
    element
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As Poderosa 4 writes it on Japanese Windows: Shift_JIS, CRLF.
    fn poderosa_file() -> Vec<u8> {
        let text = "<?xml version=\"1.0\" encoding=\"shift_jis\"?>\r\n\
            <poderosa-shortcut version=\"4.0\">\r\n  \
            <Poderosa.Terminal.TerminalSettings encoding=\"EUC_JP\" transmit-nl=\"CRLF\" caption=\"開発サーバー\" />\r\n  \
            <Poderosa.Protocols.SSHLoginParameter terminal-type=\"vt100\" destination=\"dev.example.jp\" port=\"2222\" \
            authentication=\"PublicKey\" account=\"****\" identityFileName=\"C:\\keys\\id_rsa\" \
            password=\"secret-ish\" enableAgentForwarding=\"False\" enableX11Forwarding=\"False\" />\r\n\
            </poderosa-shortcut>\r\n";
        encoding_rs::SHIFT_JIS.encode(text).0.into_owned()
    }

    #[test]
    fn reads_a_poderosa_4_shortcut() {
        let shortcut = parse(&poderosa_file()).unwrap();
        assert_eq!(
            shortcut,
            Shortcut {
                caption: "開発サーバー".to_owned(),
                protocol: Protocol::Ssh2,
                host: "dev.example.jp".to_owned(),
                port: 2222,
                user: "****".to_owned(),
                auth: Auth::PublicKey,
                key_path: r"C:\keys\id_rsa".to_owned(),
                term: "vt100".to_owned(),
                encoding: "euc-jp".to_owned(),
                newline: NewLine::CrLf,
            }
        );
    }

    #[test]
    fn defaults_are_filled_in() {
        let text = br#"<?xml version="1.0"?>
            <poderosa-shortcut version="4.0">
              <Poderosa.Terminal.TerminalSettings encoding="UTF8" caption="" />
              <Poderosa.Protocols.SSHLoginParameter destination="rocky9" account="me" />
            </poderosa-shortcut>"#;
        let shortcut = parse(text).unwrap();
        assert_eq!(shortcut.port, 22);
        assert_eq!(shortcut.auth, Auth::Password);
        assert_eq!(shortcut.term, "xterm");
        assert_eq!(shortcut.encoding, "utf-8");
        assert_eq!(shortcut.newline, NewLine::Cr);
    }

    #[test]
    fn reads_the_old_format() {
        let text = br#"<poderosa-shortcut type="tcp" host="old.example.jp" port="22" account="me"
            method="SSH2" auth="Password" encoding="Shift_JIS" terminal-type="KTerm" caption="old" />"#;
        let shortcut = parse(text).unwrap();
        assert_eq!(shortcut.host, "old.example.jp");
        assert_eq!(shortcut.user, "me");
        assert_eq!(shortcut.protocol, Protocol::Ssh2);
        assert_eq!(shortcut.encoding, "shift_jis");
        assert_eq!(shortcut.term, "kterm");
    }

    #[test]
    fn telnet_and_ssh1_are_recognised() {
        let telnet = br#"<poderosa-shortcut version="4.0">
            <Poderosa.Terminal.TerminalSettings encoding="UTF8" caption="t" />
            <Poderosa.Protocols.TelnetParameter destination="sw1" telnetNewLine="True" />
            </poderosa-shortcut>"#;
        let shortcut = parse(telnet).unwrap();
        assert_eq!((shortcut.protocol, shortcut.port), (Protocol::Telnet, 23));

        let ssh1 = br#"<poderosa-shortcut version="4.0">
            <Poderosa.Terminal.TerminalSettings encoding="UTF8" caption="t" />
            <Poderosa.Protocols.SSHLoginParameter destination="r1" method="SSH1" account="a" />
            </poderosa-shortcut>"#;
        assert_eq!(parse(ssh1).unwrap().protocol, Protocol::Ssh1);
    }

    #[test]
    fn something_else_is_rejected() {
        assert!(matches!(parse(b"<html></html>"), Err(GtsError::NotAShortcut)));
        assert!(parse(b"<poderosa-shortcut").is_err());
    }

    #[test]
    fn what_is_written_reads_back_the_same() {
        let original = parse(&poderosa_file()).unwrap();
        let written = write(&original);
        assert!(written.starts_with("<?xml version=\"1.0\" encoding=\"utf-8\"?>"));
        assert!(!written.contains("password"), "{written}");
        assert_eq!(parse(written.as_bytes()).unwrap(), original);

        let mut special = original.clone();
        special.caption = r#"a "quoted" <caption> & more"#.to_owned();
        assert_eq!(parse(write(&special).as_bytes()).unwrap(), special);
    }
}
