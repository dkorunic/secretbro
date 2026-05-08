//! Linux `LD_PRELOAD` integration tests: spawn a child with the cdylib
//! preloaded, exercise one libc call, assert the outcome.
//!
//! macOS is excluded — `__interpose` re-enters our hooks from `realpath`
//! during `K8S_SECRETS` `LazyLock` init and deadlocks.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ---- helpers -------------------------------------------------------------

struct TempDir {
    path: PathBuf,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "secretbro-preload-{}-{}-{}-{}",
            std::process::id(),
            tag,
            nanos,
            n
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        let path = path.canonicalize().unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn make_secrets(root: &TempDir) -> PathBuf {
    let p = root.path().join("secrets");
    std::fs::create_dir_all(&p).unwrap();
    p.canonicalize().unwrap()
}

/// Returns the cdylib path for the test binary's target, building if missing.
/// `--target` is required on cross-builds so the `.so` matches the loader.
fn lib_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = option_env!("SECRETBRO_BUILD_TARGET");
    let dir = match target {
        Some(t) => manifest.join("target").join(t).join("debug"),
        None => manifest.join("target").join("debug"),
    };
    let lib = dir.join("libsecretbro.so");
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

/// In-child marker; parent tests set this before spawning.
fn in_child() -> bool {
    std::env::var("SECRETBRO_PRELOAD_CHILD").is_ok()
}

fn child_str(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(|_| panic!("missing child env var {key}"))
}

fn child_path(key: &str) -> PathBuf {
    PathBuf::from(child_str(key))
}

/// Spawns the test binary with `LD_PRELOAD` and runs the named ignored test.
fn run_child(test_name: &str, envs: &[(&str, &Path)]) -> std::process::Output {
    let me = std::env::current_exe().unwrap();
    let mut cmd = Command::new(&me);
    cmd.env_remove("LD_PRELOAD")
        .env("LD_PRELOAD", lib_path())
        .env("SECRETBRO_PRELOAD_CHILD", "1")
        .args(["--ignored", "--exact", test_name]);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to spawn child test")
}

fn assert_child_ok(test_name: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "child test `{test_name}` failed:\nstatus={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("1 passed"),
        "child `{test_name}` did not run a test:\n{stdout}"
    );
}

fn cstr(p: &Path) -> CString {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes()).unwrap()
}

// ---- read hooks: open / fopen / access / opendir / readlink --------------

#[test]
#[ignore]
fn child_open_secret_denies() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let fd = unsafe { libc::open(cs.as_ptr(), libc::O_RDONLY) };
    let err = std::io::Error::last_os_error();
    assert_eq!(fd, -1, "open should fail for secret path");
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn open_on_secret_path_returns_eacces() {
    let t = TempDir::new("open-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_open_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_open_secret_denies", &out);
}

#[test]
#[ignore]
fn child_open_non_secret_succeeds() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let fd = unsafe { libc::open(cs.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open of non-secret should succeed");
    unsafe { libc::close(fd) };
}

#[test]
fn open_on_non_secret_path_passes_through() {
    let t = TempDir::new("open-allow");
    let s = make_secrets(&t);
    let outside = t.path().join("plain");
    std::fs::write(&outside, b"x").unwrap();
    let out = run_child(
        "child_open_non_secret_succeeds",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &outside)],
    );
    assert_child_ok("child_open_non_secret_succeeds", &out);
}

#[test]
#[ignore]
fn child_creat_new_in_secrets_denies() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let fd = unsafe { libc::creat(cs.as_ptr(), 0o600) };
    let err = std::io::Error::last_os_error();
    assert_eq!(fd, -1, "creat under secrets must fail");
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn creat_on_new_file_under_secrets_denies() {
    let t = TempDir::new("creat-new");
    let s = make_secrets(&t);
    let leaf = s.join("not-yet-created");
    let out = run_child(
        "child_creat_new_in_secrets_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_creat_new_in_secrets_denies", &out);
}

#[test]
#[ignore]
fn child_fopen_secret_returns_null() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let mode = CString::new("r").unwrap();
    let fp = unsafe { libc::fopen(cs.as_ptr(), mode.as_ptr()) };
    let err = std::io::Error::last_os_error();
    assert!(fp.is_null(), "fopen of secret must return NULL");
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn fopen_on_secret_returns_null_with_eacces() {
    let t = TempDir::new("fopen-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_fopen_secret_returns_null",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_fopen_secret_returns_null", &out);
}

#[test]
#[ignore]
fn child_access_secret_denies() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let r = unsafe { libc::access(cs.as_ptr(), libc::R_OK) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn access_on_secret_denies() {
    let t = TempDir::new("access-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_access_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_access_secret_denies", &out);
}

#[test]
#[ignore]
fn child_opendir_secret_returns_null() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let dir = unsafe { libc::opendir(cs.as_ptr()) };
    let err = std::io::Error::last_os_error();
    assert!(dir.is_null());
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn opendir_on_secret_returns_null() {
    let t = TempDir::new("opendir-secret");
    let s = make_secrets(&t);
    let out = run_child(
        "child_opendir_secret_returns_null",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &s)],
    );
    assert_child_ok("child_opendir_secret_returns_null", &out);
}

// ---- modify hooks --------------------------------------------------------

#[test]
#[ignore]
fn child_chmod_secret_denies() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let r = unsafe { libc::chmod(cs.as_ptr(), 0o400) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn chmod_on_secret_denies() {
    let t = TempDir::new("chmod-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_chmod_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_chmod_secret_denies", &out);
}

#[test]
#[ignore]
fn child_unlink_secret_denies() {
    if !in_child() {
        return;
    }
    let target = child_path("SECRETBRO_TARGET");
    let cs = cstr(&target);
    let r = unsafe { libc::unlink(cs.as_ptr()) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn unlink_on_secret_denies() {
    let t = TempDir::new("unlink-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_unlink_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_unlink_secret_denies", &out);
}

// ---- two-path hooks: rename / link / symlink -----------------------------

#[test]
#[ignore]
fn child_rename_secret_to_outside_denies() {
    if !in_child() {
        return;
    }
    let src = cstr(&child_path("SECRETBRO_SRC"));
    let dst = cstr(&child_path("SECRETBRO_DST"));
    let r = unsafe { libc::rename(src.as_ptr(), dst.as_ptr()) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1, "rename(secret, outside) must fail");
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn rename_secret_to_outside_denies() {
    let t = TempDir::new("rename-out");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let dst = t.path().join("stolen");
    let out = run_child(
        "child_rename_secret_to_outside_denies",
        &[
            ("SECRETBRO_PATH", &s),
            ("SECRETBRO_SRC", &leaf),
            ("SECRETBRO_DST", &dst),
        ],
    );
    assert_child_ok("child_rename_secret_to_outside_denies", &out);
}

#[test]
#[ignore]
fn child_rename_outside_to_secret_denies() {
    if !in_child() {
        return;
    }
    let src = cstr(&child_path("SECRETBRO_SRC"));
    let dst = cstr(&child_path("SECRETBRO_DST"));
    let r = unsafe { libc::rename(src.as_ptr(), dst.as_ptr()) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1, "rename(outside, secret) must fail");
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn rename_outside_to_secret_denies() {
    let t = TempDir::new("rename-in");
    let s = make_secrets(&t);
    let src = t.path().join("plain");
    std::fs::write(&src, b"x").unwrap();
    let dst = s.join("shadow");
    let out = run_child(
        "child_rename_outside_to_secret_denies",
        &[
            ("SECRETBRO_PATH", &s),
            ("SECRETBRO_SRC", &src),
            ("SECRETBRO_DST", &dst),
        ],
    );
    assert_child_ok("child_rename_outside_to_secret_denies", &out);
}

#[test]
#[ignore]
fn child_rename_outside_to_outside_succeeds() {
    if !in_child() {
        return;
    }
    let src = cstr(&child_path("SECRETBRO_SRC"));
    let dst = cstr(&child_path("SECRETBRO_DST"));
    let r = unsafe { libc::rename(src.as_ptr(), dst.as_ptr()) };
    assert_eq!(r, 0, "rename of two non-secret paths must pass through");
}

#[test]
fn rename_outside_to_outside_passes_through() {
    let t = TempDir::new("rename-pass");
    let s = make_secrets(&t);
    let src = t.path().join("a");
    std::fs::write(&src, b"x").unwrap();
    let dst = t.path().join("b");
    let out = run_child(
        "child_rename_outside_to_outside_succeeds",
        &[
            ("SECRETBRO_PATH", &s),
            ("SECRETBRO_SRC", &src),
            ("SECRETBRO_DST", &dst),
        ],
    );
    assert_child_ok("child_rename_outside_to_outside_succeeds", &out);
}

#[test]
#[ignore]
fn child_link_outside_to_secret_denies() {
    if !in_child() {
        return;
    }
    let src = cstr(&child_path("SECRETBRO_SRC"));
    let dst = cstr(&child_path("SECRETBRO_DST"));
    let r = unsafe { libc::link(src.as_ptr(), dst.as_ptr()) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn link_outside_to_secret_denies() {
    let t = TempDir::new("link-in");
    let s = make_secrets(&t);
    let src = t.path().join("src");
    std::fs::write(&src, b"x").unwrap();
    let dst = s.join("hardlink");
    let out = run_child(
        "child_link_outside_to_secret_denies",
        &[
            ("SECRETBRO_PATH", &s),
            ("SECRETBRO_SRC", &src),
            ("SECRETBRO_DST", &dst),
        ],
    );
    assert_child_ok("child_link_outside_to_secret_denies", &out);
}

// ---- Linux-only hooks: stat / openat / mkdirat / renameat ---------------

#[test]
#[ignore]
fn child_stat_secret_denies() {
    if !in_child() {
        return;
    }
    let target = cstr(&child_path("SECRETBRO_TARGET"));
    let mut buf: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::stat(target.as_ptr(), &mut buf) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn stat_on_secret_denies() {
    let t = TempDir::new("stat-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_stat_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_stat_secret_denies", &out);
}

#[test]
#[ignore]
fn child_openat_secret_denies() {
    if !in_child() {
        return;
    }
    let target = cstr(&child_path("SECRETBRO_TARGET"));
    let fd = unsafe {
        libc::openat(libc::AT_FDCWD, target.as_ptr(), libc::O_RDONLY)
    };
    let err = std::io::Error::last_os_error();
    assert_eq!(fd, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn openat_on_secret_denies() {
    let t = TempDir::new("openat-secret");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_openat_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_openat_secret_denies", &out);
}

#[test]
#[ignore]
fn child_mkdirat_secret_denies() {
    if !in_child() {
        return;
    }
    let target = cstr(&child_path("SECRETBRO_TARGET"));
    let r = unsafe { libc::mkdirat(libc::AT_FDCWD, target.as_ptr(), 0o700) };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn mkdirat_on_secret_denies() {
    let t = TempDir::new("mkdirat-secret");
    let s = make_secrets(&t);
    let new_dir = s.join("new-subdir");
    let out = run_child(
        "child_mkdirat_secret_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &new_dir)],
    );
    assert_child_ok("child_mkdirat_secret_denies", &out);
}

#[test]
#[ignore]
fn child_renameat_outside_to_secret_denies() {
    if !in_child() {
        return;
    }
    let src = cstr(&child_path("SECRETBRO_SRC"));
    let dst = cstr(&child_path("SECRETBRO_DST"));
    let r = unsafe {
        libc::renameat(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
        )
    };
    let err = std::io::Error::last_os_error();
    assert_eq!(r, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn renameat_outside_to_secret_denies() {
    let t = TempDir::new("renameat-in");
    let s = make_secrets(&t);
    let src = t.path().join("plain");
    std::fs::write(&src, b"x").unwrap();
    let dst = s.join("shadow");
    let out = run_child(
        "child_renameat_outside_to_secret_denies",
        &[
            ("SECRETBRO_PATH", &s),
            ("SECRETBRO_SRC", &src),
            ("SECRETBRO_DST", &dst),
        ],
    );
    assert_child_ok("child_renameat_outside_to_secret_denies", &out);
}

// ---- env / no-op behavior ------------------------------------------------

#[test]
#[ignore]
fn child_env_override_takes_effect() {
    if !in_child() {
        return;
    }
    // Custom SECRETBRO_PATH dir must be denied; default `/var/run/...` is unrelated.
    let target = cstr(&child_path("SECRETBRO_TARGET"));
    let fd = unsafe { libc::open(target.as_ptr(), libc::O_RDONLY) };
    let err = std::io::Error::last_os_error();
    assert_eq!(fd, -1, "SECRETBRO_PATH override should deny");
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn secretbro_path_env_override_changes_protected_dir() {
    let t = TempDir::new("env-override");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let out = run_child(
        "child_env_override_takes_effect",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &leaf)],
    );
    assert_child_ok("child_env_override_takes_effect", &out);
}

#[test]
#[ignore]
fn child_open_when_secrets_dir_missing() {
    if !in_child() {
        return;
    }
    // Missing secrets dir → K8S_SECRETS = None → hooks no-op; unrelated I/O still works.
    let target = cstr(&child_path("SECRETBRO_TARGET"));
    let fd = unsafe { libc::open(target.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "lib must not break I/O when secrets dir missing");
    unsafe { libc::close(fd) };
}

#[test]
fn missing_secrets_dir_makes_lib_a_no_op() {
    let t = TempDir::new("missing-dir");
    let nonexistent = t.path().join("does-not-exist");
    let plain = t.path().join("plain");
    std::fs::write(&plain, b"x").unwrap();
    let out = run_child(
        "child_open_when_secrets_dir_missing",
        &[("SECRETBRO_PATH", &nonexistent), ("SECRETBRO_TARGET", &plain)],
    );
    assert_child_ok("child_open_when_secrets_dir_missing", &out);
}

#[test]
#[ignore]
fn child_open_via_symlink_to_secrets_denies() {
    if !in_child() {
        return;
    }
    // Symlink redirects into secrets must be caught via canonicalization.
    let target = cstr(&child_path("SECRETBRO_TARGET"));
    let fd = unsafe { libc::open(target.as_ptr(), libc::O_RDONLY) };
    let err = std::io::Error::last_os_error();
    assert_eq!(fd, -1);
    assert_eq!(err.raw_os_error(), Some(libc::EACCES));
}

#[test]
fn open_via_symlink_into_secrets_denies() {
    let t = TempDir::new("symlink-in");
    let s = make_secrets(&t);
    let leaf = s.join("token");
    std::fs::write(&leaf, b"x").unwrap();
    let alias = t.path().join("alias");
    std::os::unix::fs::symlink(&s, &alias).unwrap();
    let via = alias.join("token");
    let out = run_child(
        "child_open_via_symlink_to_secrets_denies",
        &[("SECRETBRO_PATH", &s), ("SECRETBRO_TARGET", &via)],
    );
    assert_child_ok("child_open_via_symlink_to_secrets_denies", &out);
}

// ---- symbol export sanity (M-076: dropped #[no_mangle]) -----------------

#[test]
fn cdylib_exports_open_symbol() {
    // `LD_PRELOAD` interposition needs unmangled libc names exported.
    let lib = lib_path();
    let nm = Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(&lib)
        .output()
        .expect("nm must be available");
    let out = String::from_utf8_lossy(&nm.stdout);
    for sym in ["open", "creat", "fopen", "rename", "stat", "chmod"] {
        assert!(
            out.lines().any(|l| l.split_whitespace().last() == Some(sym)),
            "missing exported symbol `{sym}` in {}:\n{out}",
            lib.display(),
        );
    }
}
