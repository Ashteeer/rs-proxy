use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .args(["--version", "--verbose"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(
            || "unavailable".to_owned(),
            |output| String::from_utf8_lossy(&output.stdout).replace('\n', " | "),
        );
    println!("cargo:rustc-env=RS_PROXY_BENCH_RUSTC={version}");
}
