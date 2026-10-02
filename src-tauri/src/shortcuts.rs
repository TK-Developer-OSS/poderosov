//! Poderosa shortcut files (`*.gts`): opening, saving, and the list shown in
//! the File menu, which holds those in the current folder, those next to the
//! executable, and the ones opened or saved lately.

use std::fs;
use std::path::{Path, PathBuf};

use poderosov_core::gts::{self, Auth, NewLine, Protocol};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

/// How many recently opened or saved shortcut files are remembered.
const RECENT_SIZE: usize = 10;

/// A shortcut as the front end handles it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Shortcut {
    caption: String,
    /// `ssh2`; `ssh1` and `telnet` only come from files and cannot be opened yet.
    protocol: String,
    host: String,
    port: u16,
    user: String,
    /// `password`, `publicKey` or `keyboardInteractive`.
    auth: String,
    key_path: String,
    term: String,
    encoding: String,
    /// `CR`, `LF` or `CRLF`.
    newline: String,
}

impl From<gts::Shortcut> for Shortcut {
    fn from(shortcut: gts::Shortcut) -> Self {
        Self {
            caption: shortcut.caption,
            protocol: match shortcut.protocol {
                Protocol::Ssh2 => "ssh2",
                Protocol::Ssh1 => "ssh1",
                Protocol::Telnet => "telnet",
            }
            .to_owned(),
            host: shortcut.host,
            port: shortcut.port,
            user: shortcut.user,
            auth: match shortcut.auth {
                Auth::Password => "password",
                Auth::PublicKey => "publicKey",
                Auth::KeyboardInteractive => "keyboardInteractive",
            }
            .to_owned(),
            key_path: shortcut.key_path,
            term: shortcut.term,
            encoding: shortcut.encoding,
            newline: shortcut.newline.name().to_owned(),
        }
    }
}

impl From<Shortcut> for gts::Shortcut {
    fn from(shortcut: Shortcut) -> Self {
        Self {
            caption: shortcut.caption,
            protocol: Protocol::Ssh2,
            host: shortcut.host,
            port: shortcut.port,
            user: shortcut.user,
            auth: match shortcut.auth.as_str() {
                "publicKey" => Auth::PublicKey,
                "keyboardInteractive" => Auth::KeyboardInteractive,
                _ => Auth::Password,
            },
            key_path: shortcut.key_path,
            term: shortcut.term,
            encoding: shortcut.encoding,
            newline: match shortcut.newline.as_str() {
                "LF" => NewLine::Lf,
                "CRLF" => NewLine::CrLf,
                _ => NewLine::Cr,
            },
        }
    }
}

/// A shortcut file found for the File menu.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListedShortcut {
    path: PathBuf,
    shortcut: Shortcut,
}

fn read(path: &Path) -> Result<Shortcut, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    gts::parse(&bytes).map(Shortcut::from).map_err(|error| error.to_string())
}

fn recent_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(crate::paths::config_dir(app)?.join("recent-shortcuts.json"))
}

fn load_recent(app: &AppHandle) -> Vec<PathBuf> {
    recent_path(app)
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Puts `path` first among the recent shortcut files.
fn remember(app: &AppHandle, path: &Path) {
    let mut recent = load_recent(app);
    recent.retain(|other| other != path);
    recent.insert(0, path.to_owned());
    recent.truncate(RECENT_SIZE);
    let Ok(file) = recent_path(app) else { return };
    if let Some(directory) = file.parent() {
        let _ = fs::create_dir_all(directory);
    }
    if let Ok(text) = serde_json::to_string_pretty(&recent) {
        let _ = fs::write(file, text);
    }
}

/// `*.gts` directly in `directory`, by name.
fn shortcut_files_in(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("gts"))
        })
        .collect();
    files.sort();
    files
}

#[tauri::command]
pub fn gts_open(app: AppHandle, path: PathBuf) -> Result<Shortcut, String> {
    let shortcut = read(&path)?;
    remember(&app, &path);
    Ok(shortcut)
}

#[tauri::command]
pub fn gts_save(app: AppHandle, path: PathBuf, shortcut: Shortcut) -> Result<(), String> {
    fs::write(&path, gts::write(&shortcut.into())).map_err(|error| error.to_string())?;
    remember(&app, &path);
    Ok(())
}

/// Shortcut files for the File menu: recent ones first, then those in the
/// current folder and next to the executable. Files that no longer exist or
/// cannot be read are left out.
#[tauri::command]
pub fn gts_list(app: AppHandle) -> Vec<ListedShortcut> {
    let mut paths = load_recent(&app);
    let mut folders = Vec::new();
    if let Ok(current) = std::env::current_dir() {
        folders.push(current);
    }
    if let Some(beside_exe) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_owned)) {
        folders.push(beside_exe);
    }
    for folder in folders {
        paths.extend(shortcut_files_in(&folder));
    }

    let mut seen = Vec::new();
    let mut listed = Vec::new();
    for path in paths {
        let key = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if let Ok(shortcut) = read(&path) {
            listed.push(ListedShortcut { path, shortcut });
        }
    }
    listed
}
