fn main() {
    // The front end is compiled into the binary, so a change to it needs a rebuild.
    println!("cargo:rerun-if-changed=../ui");
    tauri_build::build();
}
