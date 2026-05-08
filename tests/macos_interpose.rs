//! macOS-specific dylib structure checks.
//!
//! Real `DYLD_INSERT_LIBRARIES` integration deadlocks on this codebase
//! during process init (libsystem's `realpath` re-enters our hooks while
//! the `K8S_SECRETS` `LazyLock` is mid-init). These tests instead inspect
//! the built dylib so that mutations to the macOS interpose machinery are
//! still caught at the binary-shape level.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::Command;

fn lib_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib = manifest.join("target").join("debug").join("libsecretbro.dylib");
    if !lib.exists() {
        let status = Command::new("cargo")
            .args(["build"])
            .current_dir(&manifest)
            .status()
            .expect("failed to spawn cargo build");
        assert!(status.success(), "cargo build failed");
    }
    assert!(lib.exists(), "cdylib still missing: {}", lib.display());
    lib
}

fn interpose_dump() -> String {
    let out = Command::new("otool")
        .args(["-s", "__DATA", "__interpose"])
        .arg(lib_path())
        .output()
        .expect("otool must be available");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn interpose_section_is_present_and_non_empty() {
    // Drops of `#[link_section = "__DATA,__interpose"]` or `#[used]` would
    // leave dyld with no entries to process — hooks never activate.
    let dump = interpose_dump();
    assert!(
        dump.contains("(__DATA,__interpose) section"),
        "missing __interpose section:\n{dump}"
    );
    let entries = dump.lines().filter(|l| l.starts_with('0')).count();
    assert!(entries > 0, "__interpose section is empty:\n{dump}");
}

#[test]
fn interpose_entry_count_matches_cross_platform_hooks() {
    // 21 cross-platform hooks each contribute one 16-byte
    // `Interpose { _new, _old }` entry. otool prints one entry per line.
    let dump = interpose_dump();
    let entries = dump.lines().filter(|l| l.starts_with('0')).count();
    assert_eq!(entries, 21, "unexpected hook count in __interpose:\n{dump}");
}

#[test]
fn macos_does_not_export_linux_only_hooks() {
    // `stat`/`openat`/etc. are gated `#[cfg(target_os = "linux")]`.
    // Dropping the gate (M-056) would expose them on macOS where they
    // can't intercept the mangled `stat$INODE64` symbols.
    let out = Command::new("nm")
        .args(["-gU"])
        .arg(lib_path())
        .output()
        .expect("nm must be available");
    let symbols = String::from_utf8_lossy(&out.stdout);
    for forbidden in [
        " _stat\n",
        " _lstat\n",
        " _fstatat\n",
        " _faccessat\n",
        " _readlinkat\n",
        " _name_to_handle_at\n",
    ] {
        assert!(
            !symbols.contains(forbidden),
            "Linux-only symbol leaked into macOS dylib: `{}`\n{symbols}",
            forbidden.trim()
        );
    }
}
