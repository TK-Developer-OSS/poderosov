//! The options the user sets once for every session, kept in `options.json`
//! in the application's configuration directory.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Options {
    /// A CSS font-family list: the first font that has a character draws it.
    font_family: String,
    /// In points.
    font_size: f64,
    /// What new connections start out with, as a WHATWG label.
    encoding: String,
    /// Terminal colours, as `#rrggbb`.
    foreground_color: String,
    background_color: String,
    /// Opacity of the terminal background colour in percent, laid over the
    /// window colour; the text stays solid.
    background_opacity: u8,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            font_family: r#""Courier New", "MS Gothic", Menlo, "DejaVu Sans Mono", monospace"#
                .to_owned(),
            font_size: 10.5,
            encoding: "utf-8".to_owned(),
            foreground_color: "#000000".to_owned(),
            background_color: "#ffffff".to_owned(),
            background_opacity: 100,
        }
    }
}

fn options_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app.path().app_config_dir().map_err(|error| error.to_string())?;
    Ok(directory.join("options.json"))
}

/// The saved options, or the defaults where nothing (valid) was saved.
#[tauri::command]
pub fn options_load(app: AppHandle) -> Options {
    options_path(&app)
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

#[tauri::command]
pub fn options_save(app: AppHandle, options: Options) -> Result<(), String> {
    let path = options_path(&app)?;
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    }
    let text = serde_json::to_string_pretty(&options).map_err(|error| error.to_string())?;
    fs::write(path, text).map_err(|error| error.to_string())
}
