// SPDX-FileCopyrightText: 2025 Dinko Korunic <dinko.korunic@gmail.com>
//
// SPDX-License-Identifier: MIT

// Aliases -lgcc_s to Rust's bundled libunwind.a so musl cdylibs link
// without a system libgcc_s.so.1.
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let target = match env::var("TARGET") {
        Ok(t) => t,
        Err(_) => return,
    };
    // Expose TARGET to integration tests when cross-building so they can
    // locate the cdylib in target/<triple>/debug/ and pass --target to
    // their `cargo build` fallback. Skipped when TARGET == HOST so plain
    // `cargo test` keeps writing to target/debug/.
    if let Ok(host) = env::var("HOST") {
        if host != target {
            println!("cargo:rustc-env=SECRETBRO_BUILD_TARGET={target}");
        }
    }
    println!("cargo:rerun-if-env-changed=HOST");
    if !target.ends_with("-linux-musl") {
        return;
    }
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = match Command::new(&rustc)
        .args(["--print", "target-libdir", "--target", &target])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return,
    };
    let libdir = match String::from_utf8(out.stdout) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return,
    };
    let unwind = Path::new(&libdir).join("self-contained").join("libunwind.a");
    if !unwind.exists() {
        return;
    }
    let out_dir = match env::var("OUT_DIR") {
        Ok(d) => d,
        Err(_) => return,
    };
    let stub_dir = Path::new(&out_dir).join("musl-stub");
    fs::create_dir_all(&stub_dir).expect("create musl-stub OUT_DIR");
    let stub = stub_dir.join("libgcc_s.so");
    fs::write(&stub, format!("INPUT( {} )\n", unwind.display()))
        .expect("write libgcc_s.so stub");
    println!("cargo:rustc-link-search=native={}", stub_dir.display());
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=RUSTC");
}
