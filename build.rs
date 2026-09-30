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
    let Ok(target) = env::var("TARGET") else {
        return;
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
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    // macOS `open` hook: C-variadic definitions (stable since Rust 1.99)
    // read `mode` where libc's variadic prototype passes it (the stack on
    // Apple arm64). Older rustc falls back to a fixed-`mode` hook that is
    // only ABI-correct on x86_64.
    println!("cargo:rustc-check-cfg=cfg(secretbro_c_variadic)");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        if rustc_minor(&rustc).is_some_and(|m| m >= 99) {
            println!("cargo:rustc-cfg=secretbro_c_variadic");
        } else if target.starts_with("aarch64") {
            println!(
                "cargo:warning=rustc < 1.99: open(O_CREAT) mode is \
                 unreliable on Apple arm64; build with rustc >= 1.99"
            );
        }
    }
    if !target.ends_with("-linux-musl") {
        return;
    }
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
    let Ok(out_dir) = env::var("OUT_DIR") else {
        return;
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

/// Minor version of `rustc` (`99` for `1.99.0-nightly`), if parseable.
fn rustc_minor(rustc: &str) -> Option<u32> {
    let out = Command::new(rustc).arg("-vV").output().ok()?;
    let stdout = String::from_utf8(out.stdout).ok()?;
    let release = stdout.lines().find_map(|l| l.strip_prefix("release: "))?;
    release.split('.').nth(1)?.parse().ok()
}
