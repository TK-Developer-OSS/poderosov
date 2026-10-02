//! Where PoderosoV keeps its settings, history and known hosts.

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

/// The folder that, next to the executable, makes PoderosoV portable.
const PORTABLE_FOLDER: &str = "settings";

/// `settings` next to the executable if that folder exists, so that a
/// portable copy keeps everything with it; otherwise the per-user
/// configuration folder (`%APPDATA%\org.poderosov.terminal` on Windows).
pub fn config_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let portable = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|folder| folder.join(PORTABLE_FOLDER)))
        .filter(|folder| folder.is_dir());
    match portable {
        Some(folder) => Ok(folder),
        None => app.path().app_config_dir().map_err(|error| error.to_string()),
    }
}
