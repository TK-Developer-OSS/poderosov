// A release build on Windows should not open a console window next to the GUI.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod history;
mod options;
mod paths;
mod sessions;
mod shortcuts;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(sessions::Sessions::default())
        .manage(sessions::Passwords::default())
        .invoke_handler(tauri::generate_handler![
            history::history_load,
            history::history_save,
            options::options_load,
            options::options_save,
            sessions::password_remembered,
            sessions::ssh_connect,
            sessions::host_key_reply,
            sessions::session_write,
            sessions::session_write_bytes,
            sessions::session_resize,
            sessions::session_ack,
            sessions::session_close,
            sessions::session_configure,
            shortcuts::gts_open,
            shortcuts::gts_save,
            shortcuts::gts_list,
            sessions::xmodem_send,
            sessions::xmodem_cancel,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start PoderosoV");
}
