//! Recent connections, kept in `history.json` in the application's
//! configuration directory so that the login dialog can offer them again.
//!
//! The front end decides what an entry holds. Whatever it sends, passwords
//! and passphrases are dropped before anything is written.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use tauri::AppHandle;

/// Fields that must never reach the disk.
const SECRETS: &[&str] = &["password", "passphrase"];

fn history_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(crate::paths::config_dir(app)?.join("history.json"))
}

/// The saved connections, most recent first; empty if there are none.
#[tauri::command]
pub fn history_load(app: AppHandle) -> Vec<Value> {
    history_path(&app)
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

#[tauri::command]
pub fn history_save(app: AppHandle, mut entries: Vec<Value>) -> Result<(), String> {
    for entry in &mut entries {
        if let Value::Object(fields) = entry {
            fields.retain(|name, _| !SECRETS.contains(&name.as_str()));
        }
    }
    let path = history_path(&app)?;
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    }
    let text = serde_json::to_string_pretty(&entries).map_err(|error| error.to_string())?;
    fs::write(path, text).map_err(|error| error.to_string())
}
