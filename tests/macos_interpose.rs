// SPDX-FileCopyrightText: 2025 Dinko Korunic <dinko.korunic@gmail.com>
//
// SPDX-License-Identifier: MIT

//! macOS dylib structure checks.
//!
//! Real `DYLD_INSERT_LIBRARIES` deadlocks here — `__interpose` re-enters
//! our hooks from `realpath` during `K8S_SECRETS` init. Inspect the built
//! dylib instead so interpose-machinery regressions still fail.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::process::Command;

fn lib_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = option_env!("SECRETBRO_BUILD_TARGET");
    let dir = match target {
        Some(t) => manifest.join("target").join(t).join("debug"),
        None => manifest.join("target").join("debug"),
    };
    let lib = dir.join("libsecretbro.dylib");
    if !lib.exists() {
        let mut cmd = Command::new("cargo");
        cmd.arg("build").current_dir(&manifest);
        if let Some(t) = target {
            cmd.args(["--target", t]);
        }
        let status = cmd.status().expect("failed to spawn cargo build");
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
    // Without `#[link_section]` or `#[used]`, dyld sees no entries and hooks never fire.
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
    // 18 cross-platform hooks → 18 `Interpose { _new, _old }` entries; otool prints one per line.
    // The read-only metadata hooks (access, readlink, opendir) were dropped to
    // keep hot-path callers off `realpath` (see issue #818); only content
    // read/write and modify hooks remain.
    let dump = interpose_dump();
    let entries = dump.lines().filter(|l| l.starts_with('0')).count();
    assert_eq!(entries, 18, "unexpected hook count in __interpose:\n{dump}");
}

#[test]
fn macos_does_not_export_linux_only_hooks() {
    // Linux-only hooks can't intercept macOS's mangled `stat$INODE64`;
    // dropping the `cfg` gate (M-056) would leak them.
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
