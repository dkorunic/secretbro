// SPDX-FileCopyrightText: 2025 Dinko Korunic <dinko.korunic@gmail.com>
//
// SPDX-License-Identifier: MIT

//! `secretbro` denies filesystem access to the Kubernetes secrets directory
//! (`/var/run/secrets/kubernetes.io` by default) for an unmodified host
//! process.
//!
//! It ships as a `cdylib` loaded via `LD_PRELOAD` (Linux) or
//! `DYLD_INSERT_LIBRARIES` (macOS), interposing the libc filesystem entry
//! points. Each hooked call canonicalizes the path through a single
//! chokepoint (`is_secret_path` / `either_secret`); paths resolving into the
//! protected directory return the libc error sentinel with `errno = EACCES`,
//! while everything else forwards to the real libc symbol so unrelated I/O is
//! untouched.
//!
//! The protected directory is resolved once on first hook call and is
//! overridable via the `SECRETBRO_PATH` environment variable. If it can't be
//! resolved the library becomes a no-op rather than aborting the host.
//!
//! Hook bodies and path-decision logic live in this module; the `hook!` /
//! `real!` macros that bridge to the platform interposition mechanism live in
//! the `hook` module.

#[macro_use]
mod hook;

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::LazyLock;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use libc::c_uint;
use libc::{c_char, c_int, mode_t, FILE};

const K8S_SECRETS_PATH: &str = "/var/run/secrets/kubernetes.io";

/// Canonicalized secrets directory. `None` makes every hook a no-op so a
/// missing directory doesn't abort the host (release uses `panic = "abort"`).
/// Source overridable via `SECRETBRO_PATH`, read once on first hook call.
static K8S_SECRETS: LazyLock<Option<PathBuf>> = LazyLock::new(|| {
    let p = std::env::var("SECRETBRO_PATH")
        .unwrap_or_else(|_| K8S_SECRETS_PATH.to_owned());
    Path::new(&p).canonicalize().ok()
});

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!(
    "secretbro supports only target_os = \"linux\" or \"macos\"; \
     extend get_errno() to add a new platform"
);

/// Returns a pointer to the current value of errno.
unsafe fn get_errno() -> *mut c_int {
    unsafe {
        #[cfg(target_os = "linux")]
        return libc::__errno_location();

        #[cfg(target_os = "macos")]
        return libc::__error();
    }
}

/// Decides whether a path resolves into `secrets` (which must already be
/// canonicalized).
///
/// Always canonicalizes via `realpath` so symlink redirects into secrets are
/// detected. Indeterminate inputs (empty path, uncanonicalizable parent)
/// return `false` so unrelated I/O isn't broken.
fn is_path_under_secrets(pathname_bytes: &[u8], secrets: &Path) -> bool {
    if pathname_bytes.is_empty() {
        return false;
    }

    // Paths are arbitrary bytes; `to_string_lossy` would corrupt non-UTF8
    // components and mismatch libc's view. Use raw bytes.
    let path = Path::new(OsStr::from_bytes(pathname_bytes));

    let canonical = match path.canonicalize() {
        Ok(p) => p,
        // Leaf missing (e.g. `creat()` of a new file): resolve the parent
        // and re-attach the leaf so creates into secrets are still caught.
        Err(_) => match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => match parent.canonicalize() {
                Ok(mut resolved) => {
                    resolved.push(name);
                    resolved
                }
                Err(_) => return false,
            },
            _ => return false,
        },
    };

    canonical.starts_with(secrets)
}

/// True iff `pathname` resolves into the secrets directory; on true sets
/// `errno = EACCES` so callers can just return the libc error sentinel.
/// Indeterminate inputs (null, empty, no configured secrets, uncanonicalizable
/// parent) return false to avoid breaking unrelated I/O.
///
/// Limitations: TOCTOU is unavoidable for path-based interposition. See
/// README.md for the threat model.
///
/// # Safety
/// `pathname` must be NULL or a NUL-terminated C string.
unsafe fn is_secret_path(pathname: *const c_char) -> bool {
    unsafe { is_secret_path_with(pathname, K8S_SECRETS.as_deref()) }
}

/// Test-friendly inner form of `is_secret_path`; takes secrets explicitly
/// so the `None` branch is unit-testable without the global `LazyLock`.
///
/// # Safety
/// `pathname` must be NULL or a NUL-terminated C string.
unsafe fn is_secret_path_with(
    pathname: *const c_char,
    secrets: Option<&Path>,
) -> bool {
    if pathname.is_null() {
        return false;
    }
    let Some(secrets) = secrets else {
        return false;
    };
    let bytes = unsafe { CStr::from_ptr(pathname).to_bytes() };

    // `is_path_under_secrets` calls `realpath`, which sets errno on failure
    // for any non-existent allow-path. Snapshot errno so the miss branch
    // doesn't perturb it before the caller forwards to real libc.
    let saved_errno = unsafe { *get_errno() };
    if is_path_under_secrets(bytes, secrets) {
        unsafe { get_errno().write(libc::EACCES) };
        true
    } else {
        unsafe { get_errno().write(saved_errno) };
        false
    }
}

/// True if either path resolves into secrets; used by two-path operations
/// (rename, link, symlink, *at variants).
///
/// # Safety
/// Both pointers must be NULL or NUL-terminated C strings.
unsafe fn either_secret(p1: *const c_char, p2: *const c_char) -> bool {
    unsafe { either_secret_with(p1, p2, K8S_SECRETS.as_deref()) }
}

/// Test-friendly inner form of `either_secret`; takes secrets explicitly
/// so behavior is unit-testable without the global `LazyLock`.
///
/// # Safety
/// Both pointers must be NULL or NUL-terminated C strings.
unsafe fn either_secret_with(
    p1: *const c_char,
    p2: *const c_char,
    secrets: Option<&Path>,
) -> bool {
    unsafe {
        is_secret_path_with(p1, secrets) || is_secret_path_with(p2, secrets)
    }
}

// ---------------------------------------------------------------------------
// Hooks
//
// `open`/`openat` and `*64` variants are variadic in C; `hook!` can't model
// varargs, so `mode` is declared fixed. On AMD64 SysV / AArch64 AAPCS, libc
// ignores the unused register when `O_CREAT` is absent — strict ABI
// mismatch, benign on these targets.
// ---------------------------------------------------------------------------

/* int creat(const char *pathname, mode_t mode); */
hook! {
    unsafe fn creat(pathname: *const c_char, mode: mode_t) -> c_int => my_creat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(creat)(pathname, mode)
            }
        }
    }
}

/* int open(const char *pathname, int flags, mode_t mode); */
hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(open)(pathname, flags, mode)
            }
        }
    }
}

/* int openat(int dirfd, const char *pathname, int flags, mode_t mode); */
hook! {
    unsafe fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(openat)(dirfd, pathname, flags, mode)
            }
        }
    }
}

/* FILE *fopen(const char *path, const char *mode); */
hook! {
    unsafe fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen {
        unsafe {
            if is_secret_path(pathname) {
                null_mut()
            } else {
                real!(fopen)(pathname, mode)
            }
        }
    }
}

/* FILE *freopen(const char *path, const char *mode, FILE *stream); */
hook! {
    unsafe fn freopen(pathname: *const c_char, mode: *const c_char, file: *mut FILE) -> *mut FILE => my_freopen {
        unsafe {
            if is_secret_path(pathname) {
                null_mut()
            } else {
                real!(freopen)(pathname, mode, file)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-platform modify hooks
//
// Block creation, deletion, and metadata mutation of paths in secrets.
// Two-path operations deny if either side is in secrets, so a secret can't
// be moved out or shadowed.
// ---------------------------------------------------------------------------

/* int mkdir(const char *pathname, mode_t mode); */
hook! {
    unsafe fn mkdir(pathname: *const c_char, mode: mode_t) -> c_int => my_mkdir {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(mkdir)(pathname, mode)
            }
        }
    }
}

/* int rmdir(const char *pathname); */
hook! {
    unsafe fn rmdir(pathname: *const c_char) -> c_int => my_rmdir {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(rmdir)(pathname)
            }
        }
    }
}

/* int unlink(const char *pathname); */
hook! {
    unsafe fn unlink(pathname: *const c_char) -> c_int => my_unlink {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(unlink)(pathname)
            }
        }
    }
}

/* int truncate(const char *path, off_t length); */
hook! {
    unsafe fn truncate(pathname: *const c_char, length: libc::off_t) -> c_int => my_truncate {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(truncate)(pathname, length)
            }
        }
    }
}

/* int chmod(const char *pathname, mode_t mode); */
hook! {
    unsafe fn chmod(pathname: *const c_char, mode: mode_t) -> c_int => my_chmod {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(chmod)(pathname, mode)
            }
        }
    }
}

/* int chown(const char *pathname, uid_t owner, gid_t group); */
hook! {
    unsafe fn chown(pathname: *const c_char, owner: libc::uid_t, group: libc::gid_t) -> c_int => my_chown {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(chown)(pathname, owner, group)
            }
        }
    }
}

/* int lchown(const char *pathname, uid_t owner, gid_t group); */
hook! {
    unsafe fn lchown(pathname: *const c_char, owner: libc::uid_t, group: libc::gid_t) -> c_int => my_lchown {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(lchown)(pathname, owner, group)
            }
        }
    }
}

/* int utime(const char *filename, const struct utimbuf *times); */
hook! {
    unsafe fn utime(pathname: *const c_char, times: *const libc::utimbuf) -> c_int => my_utime {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(utime)(pathname, times)
            }
        }
    }
}

/* int utimes(const char *filename, const struct timeval times[2]); */
hook! {
    unsafe fn utimes(pathname: *const c_char, times: *const libc::timeval) -> c_int => my_utimes {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(utimes)(pathname, times)
            }
        }
    }
}

/* int mknod(const char *pathname, mode_t mode, dev_t dev); */
hook! {
    unsafe fn mknod(pathname: *const c_char, mode: mode_t, dev: libc::dev_t) -> c_int => my_mknod {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(mknod)(pathname, mode, dev)
            }
        }
    }
}

/* int rename(const char *oldpath, const char *newpath); */
hook! {
    unsafe fn rename(oldpath: *const c_char, newpath: *const c_char) -> c_int => my_rename {
        unsafe {
            if either_secret(oldpath, newpath) {
                -1
            } else {
                real!(rename)(oldpath, newpath)
            }
        }
    }
}

/* int link(const char *oldpath, const char *newpath); */
hook! {
    unsafe fn link(oldpath: *const c_char, newpath: *const c_char) -> c_int => my_link {
        unsafe {
            if either_secret(oldpath, newpath) {
                -1
            } else {
                real!(link)(oldpath, newpath)
            }
        }
    }
}

/* int symlink(const char *target, const char *linkpath); */
hook! {
    unsafe fn symlink(target: *const c_char, linkpath: *const c_char) -> c_int => my_symlink {
        unsafe {
            if either_secret(target, linkpath) {
                -1
            } else {
                real!(symlink)(target, linkpath)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Linux-only modify hooks (`*at` variants)
// ---------------------------------------------------------------------------

/* int mkdirat(int dirfd, const char *pathname, mode_t mode); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn mkdirat(dirfd: c_int, pathname: *const c_char, mode: mode_t) -> c_int => my_mkdirat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(mkdirat)(dirfd, pathname, mode)
            }
        }
    }
}

/* int unlinkat(int dirfd, const char *pathname, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn unlinkat(dirfd: c_int, pathname: *const c_char, flags: c_int) -> c_int => my_unlinkat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(unlinkat)(dirfd, pathname, flags)
            }
        }
    }
}

/* int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn fchmodat(dirfd: c_int, pathname: *const c_char, mode: mode_t, flags: c_int) -> c_int => my_fchmodat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(fchmodat)(dirfd, pathname, mode, flags)
            }
        }
    }
}

/* int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn fchownat(dirfd: c_int, pathname: *const c_char, owner: libc::uid_t, group: libc::gid_t, flags: c_int) -> c_int => my_fchownat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(fchownat)(dirfd, pathname, owner, group, flags)
            }
        }
    }
}

/* int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn mknodat(dirfd: c_int, pathname: *const c_char, mode: mode_t, dev: libc::dev_t) -> c_int => my_mknodat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(mknodat)(dirfd, pathname, mode, dev)
            }
        }
    }
}

/* int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn utimensat(dirfd: c_int, pathname: *const c_char, times: *const libc::timespec, flags: c_int) -> c_int => my_utimensat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(utimensat)(dirfd, pathname, times, flags)
            }
        }
    }
}

/* int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn renameat(olddirfd: c_int, oldpath: *const c_char, newdirfd: c_int, newpath: *const c_char) -> c_int => my_renameat {
        unsafe {
            if either_secret(oldpath, newpath) {
                -1
            } else {
                real!(renameat)(olddirfd, oldpath, newdirfd, newpath)
            }
        }
    }
}

/* int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn linkat(olddirfd: c_int, oldpath: *const c_char, newdirfd: c_int, newpath: *const c_char, flags: c_int) -> c_int => my_linkat {
        unsafe {
            if either_secret(oldpath, newpath) {
                -1
            } else {
                real!(linkat)(olddirfd, oldpath, newdirfd, newpath, flags)
            }
        }
    }
}

/* int symlinkat(const char *target, int newdirfd, const char *linkpath); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int => my_symlinkat {
        unsafe {
            if either_secret(target, linkpath) {
                -1
            } else {
                real!(symlinkat)(target, newdirfd, linkpath)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// glibc Linux LFS variants
//
// The `*64` symbols are a glibc convention for explicit 64-bit `off_t`;
// they don't exist on musl (64-bit `off_t` natively) or on macOS.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn creat64(pathname: *const c_char, mode: mode_t) -> c_int => my_creat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(creat64)(pathname, mode)
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn open64(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(open64)(pathname, flags, mode)
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn openat64(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(openat64)(dirfd, pathname, flags, mode)
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn fopen64(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen64 {
        unsafe {
            if is_secret_path(pathname) {
                null_mut()
            } else {
                real!(fopen64)(pathname, mode)
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn freopen64(pathname: *const c_char, mode: *const c_char, file: *mut FILE) -> *mut FILE => my_freopen64 {
        unsafe {
            if is_secret_path(pathname) {
                null_mut()
            } else {
                real!(freopen64)(pathname, mode, file)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// glibc Linux modify variants
//
// `truncate64` is the LFS variant of `truncate`. `renameat2` is glibc 2.28+
// (the underlying syscall is Linux-only).
// ---------------------------------------------------------------------------

/* int truncate64(const char *path, off64_t length); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn truncate64(pathname: *const c_char, length: libc::off64_t) -> c_int => my_truncate64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(truncate64)(pathname, length)
            }
        }
    }
}

/* int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn renameat2(olddirfd: c_int, oldpath: *const c_char, newdirfd: c_int, newpath: *const c_char, flags: c_uint) -> c_int => my_renameat2 {
        unsafe {
            if either_secret(oldpath, newpath) {
                -1
            } else {
                real!(renameat2)(olddirfd, oldpath, newdirfd, newpath, flags)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    // ---- helpers ---------------------------------------------------------

    /// Temp directory under `std::env::temp_dir()`; avoids the `tempfile`
    /// dev-dep. Path canonicalized up front to dodge `/tmp -> /private/tmp`
    /// (macOS) and similar symlinks. Removed on `Drop`.
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
                "secretbro-test-{}-{}-{}-{}",
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

    /// Builds `<root>/secrets`, returning the canonical path. Caller owns
    /// the `TempDir` (drop it last).
    fn make_secrets(root: &TempDir) -> PathBuf {
        let p = root.path().join("secrets");
        std::fs::create_dir_all(&p).unwrap();
        p.canonicalize().unwrap()
    }

    fn check(path_bytes: &[u8], secrets: &Path) -> bool {
        is_path_under_secrets(path_bytes, secrets)
    }

    // ---- is_path_under_secrets -------------------------------------------

    #[test]
    fn under_secrets_empty_input() {
        let t = TempDir::new("empty");
        let s = make_secrets(&t);
        assert!(!check(b"", &s));
    }

    #[test]
    fn under_secrets_exact_dir_match() {
        let t = TempDir::new("exact");
        let s = make_secrets(&t);
        assert!(check(s.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_existing_child() {
        let t = TempDir::new("child");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        assert!(check(leaf.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_nonexistent_child_via_parent_fallback() {
        let t = TempDir::new("create");
        let s = make_secrets(&t);
        // File doesn't exist; mimics `creat()` of a new secret.
        let leaf = s.join("not-yet-created");
        assert!(check(leaf.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_outside_existing_path() {
        let t = TempDir::new("outside");
        let s = make_secrets(&t);
        let outside = t.path().join("other");
        std::fs::create_dir_all(&outside).unwrap();
        let f = outside.join("file");
        std::fs::write(&f, b"x").unwrap();
        assert!(!check(f.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_outside_nonexistent() {
        let t = TempDir::new("outside-missing");
        let s = make_secrets(&t);
        let bogus = t.path().join("does-not-exist");
        assert!(!check(bogus.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_sibling_with_similar_name() {
        let t = TempDir::new("sibling");
        let s = make_secrets(&t);
        // `<root>/secretsx` shares a textual prefix with `<root>/secrets`.
        // `Path::starts_with` compares components (not bytes), so this must
        // not match.
        let sibling = t.path().join("secretsx");
        std::fs::create_dir_all(&sibling).unwrap();
        let inside_sibling = sibling.join("file");
        std::fs::write(&inside_sibling, b"x").unwrap();
        assert!(!check(inside_sibling.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_traversal_escapes_outward() {
        // `<secrets>/../foo` resolves outside secrets even though textually
        // it begins with the secrets prefix.
        let t = TempDir::new("traversal-out");
        let s = make_secrets(&t);
        let escape = format!("{}/../escapes", s.as_os_str().to_str().unwrap());
        assert!(!check(escape.as_bytes(), &s));
    }

    #[test]
    fn under_secrets_traversal_returns_inward() {
        // `<secrets>/sub/../token` collapses back into secrets and must be
        // detected even though the leaf doesn't exist.
        let t = TempDir::new("traversal-in");
        let s = make_secrets(&t);
        std::fs::create_dir_all(s.join("sub")).unwrap();
        let evil = format!("{}/sub/../token", s.as_os_str().to_str().unwrap());
        assert!(check(evil.as_bytes(), &s));
    }

    #[test]
    fn under_secrets_double_slash_canonicalizes() {
        // `//` is a redundant component; canonicalize must collapse it and
        // the resulting path still resolves into secrets.
        let t = TempDir::new("double-slash");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let weird = format!("{}//token", s.as_os_str().to_str().unwrap());
        assert!(check(weird.as_bytes(), &s));
    }

    #[test]
    fn under_secrets_via_symlink_alias_is_detected() {
        // Symlink alias → secrets must canonicalize and resolve into
        // secrets so paths reaching secrets indirectly are still denied.
        let t = TempDir::new("symlink-alias");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let alias = t.path().join("alias-to-secrets");
        std::os::unix::fs::symlink(&s, &alias).unwrap();
        let via_alias = alias.join("token");
        assert!(check(via_alias.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_parent_fallback_pushes_leaf_name() {
        // Pushing `parent` (absolute) instead of `name` would replace the
        // canonicalized parent. Mutation guard: leaf doesn't exist, so the
        // fallback path canonicalizes the alias parent and re-attaches the
        // leaf — must still resolve under secrets.
        let t = TempDir::new("fallback-push");
        let s = make_secrets(&t);
        let alias = t.path().join("alias-to-secrets");
        std::os::unix::fs::symlink(&s, &alias).unwrap();
        let new_leaf = alias.join("not-yet-created");
        assert!(check(new_leaf.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_relative_path_is_indeterminate() {
        let t = TempDir::new("relative");
        let s = make_secrets(&t);
        // Relative path's leaf doesn't exist in cwd, so canonicalize and
        // parent-canonicalize both fail → indeterminate (false).
        assert!(!check(b"some/relative/path", &s));
    }

    // ---- is_secret_path (unsafe wrapper) ---------------------------------

    #[test]
    fn is_secret_path_null_pointer_is_safe() {
        // Must not dereference; must return false.
        let result = unsafe { is_secret_path(std::ptr::null()) };
        assert!(!result);
    }

    #[test]
    fn is_secret_path_empty_cstring_is_safe() {
        let cs = CString::new("").unwrap();
        let result = unsafe { is_secret_path(cs.as_ptr()) };
        assert!(!result);
    }

    #[test]
    fn is_secret_path_with_none_secrets_returns_false() {
        // None branch: missing/unresolvable secrets means the wrapper
        // returns false without setting errno (library no-op mode).
        let cs = CString::new("/var/run/secrets/kubernetes.io/token").unwrap();
        let result = unsafe { is_secret_path_with(cs.as_ptr(), None) };
        assert!(!result);
    }

    #[test]
    fn is_secret_path_with_some_secrets_detects_inside_path() {
        // Positive control for the explicit Some branch.
        let t = TempDir::new("with-some");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let cs = CString::new(leaf.as_os_str().as_bytes()).unwrap();
        let result = unsafe { is_secret_path_with(cs.as_ptr(), Some(&s)) };
        assert!(result);
    }

    #[test]
    fn is_secret_path_with_null_pointer_under_some_is_safe() {
        // Null pointer must short-circuit even when secrets is configured.
        let t = TempDir::new("null-under-some");
        let s = make_secrets(&t);
        let result =
            unsafe { is_secret_path_with(std::ptr::null(), Some(&s)) };
        assert!(!result);
    }

    // ---- get_errno -------------------------------------------------------

    #[test]
    fn get_errno_round_trip() {
        unsafe {
            let p = get_errno();
            assert!(!p.is_null());
            let saved = *p;
            *p = libc::EACCES;
            assert_eq!(*get_errno(), libc::EACCES);
            *p = libc::EPERM;
            assert_eq!(*get_errno(), libc::EPERM);
            *p = saved;
        }
    }

    // ---- is_secret_path errno side-effect contract -----------------------

    #[test]
    fn is_secret_path_sets_errno_eacces_on_match() {
        // Hooks rely on EACCES being set; they just return the sentinel.
        let t = TempDir::new("errno-eacces");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let cs = CString::new(leaf.as_os_str().as_bytes()).unwrap();
        unsafe {
            let saved = *get_errno();
            *get_errno() = 0;
            let result = is_secret_path_with(cs.as_ptr(), Some(&s));
            assert!(result);
            assert_eq!(*get_errno(), libc::EACCES);
            *get_errno() = saved;
        }
    }

    #[test]
    fn is_secret_path_preserves_errno_on_miss() {
        // Allow path forwards to libc; errno must pass through.
        let t = TempDir::new("errno-preserve");
        let s = make_secrets(&t);
        let cs = CString::new("/definitely/not/a/secret").unwrap();
        unsafe {
            let saved = *get_errno();
            *get_errno() = libc::EINVAL;
            let result = is_secret_path_with(cs.as_ptr(), Some(&s));
            assert!(!result);
            assert_eq!(*get_errno(), libc::EINVAL);
            *get_errno() = saved;
        }
    }

    #[test]
    fn is_secret_path_with_none_preserves_errno() {
        // Library-disabled mode: same errno contract.
        let cs = CString::new("/anything").unwrap();
        unsafe {
            let saved = *get_errno();
            *get_errno() = libc::EBADF;
            let result = is_secret_path_with(cs.as_ptr(), None);
            assert!(!result);
            assert_eq!(*get_errno(), libc::EBADF);
            *get_errno() = saved;
        }
    }

    // ---- is_path_under_secrets edge branches -----------------------------

    #[test]
    fn under_secrets_unresolvable_parent_returns_false() {
        // Indeterminate → allow, to not break unrelated I/O.
        let t = TempDir::new("missing-parent");
        let s = make_secrets(&t);
        let bogus = t.path().join("nonexistent-parent-zzz/nonexistent-leaf");
        assert!(!check(bogus.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_path_with_dotdot_leaf_returns_false() {
        // Path ending in `..` has `file_name() == None`.
        let t = TempDir::new("dotdot-leaf");
        let s = make_secrets(&t);
        let bogus = t.path().join("nonexistent-dir/..");
        assert!(!check(bogus.as_os_str().as_bytes(), &s));
    }

    #[test]
    fn under_secrets_non_utf8_path_bytes_do_not_panic() {
        // Raw-bytes path; `to_string_lossy` would corrupt non-UTF8.
        let t = TempDir::new("non-utf8");
        let s = make_secrets(&t);
        let mut bytes = s.as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(b"/\xff/leaf");
        assert!(!check(&bytes, &s));
    }

    // ---- either_secret ---------------------------------------------------

    #[test]
    fn either_secret_with_both_null_returns_false() {
        let t = TempDir::new("either-null");
        let s = make_secrets(&t);
        let result = unsafe {
            either_secret_with(std::ptr::null(), std::ptr::null(), Some(&s))
        };
        assert!(!result);
    }

    #[test]
    fn either_secret_with_first_secret_returns_true() {
        let t = TempDir::new("either-first");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let secret = CString::new(leaf.as_os_str().as_bytes()).unwrap();
        let outside = CString::new("/etc/hostname").unwrap();
        let result = unsafe {
            either_secret_with(secret.as_ptr(), outside.as_ptr(), Some(&s))
        };
        assert!(result);
    }

    #[test]
    fn either_secret_with_second_secret_returns_true() {
        let t = TempDir::new("either-second");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let outside = CString::new("/etc/hostname").unwrap();
        let secret = CString::new(leaf.as_os_str().as_bytes()).unwrap();
        let result = unsafe {
            either_secret_with(outside.as_ptr(), secret.as_ptr(), Some(&s))
        };
        assert!(result);
    }

    #[test]
    fn either_secret_with_both_outside_returns_false() {
        let t = TempDir::new("either-both-out");
        let s = make_secrets(&t);
        let p1 = CString::new("/etc/hostname").unwrap();
        let p2 = CString::new("/usr/bin/env").unwrap();
        let result =
            unsafe { either_secret_with(p1.as_ptr(), p2.as_ptr(), Some(&s)) };
        assert!(!result);
    }

    #[test]
    fn either_secret_with_both_inside_returns_true() {
        let t = TempDir::new("either-both-in");
        let s = make_secrets(&t);
        let a = s.join("a");
        let b = s.join("b");
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        let cs1 = CString::new(a.as_os_str().as_bytes()).unwrap();
        let cs2 = CString::new(b.as_os_str().as_bytes()).unwrap();
        let result = unsafe {
            either_secret_with(cs1.as_ptr(), cs2.as_ptr(), Some(&s))
        };
        assert!(result);
    }

    #[test]
    fn either_secret_with_one_null_one_secret_returns_true() {
        // Null is `false` on its side; OR carries through the secret.
        let t = TempDir::new("either-null-secret");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let secret = CString::new(leaf.as_os_str().as_bytes()).unwrap();
        let r1 = unsafe {
            either_secret_with(std::ptr::null(), secret.as_ptr(), Some(&s))
        };
        let r2 = unsafe {
            either_secret_with(secret.as_ptr(), std::ptr::null(), Some(&s))
        };
        assert!(r1);
        assert!(r2);
    }

    #[test]
    fn either_secret_with_none_secrets_returns_false() {
        // Library-disabled mode: no denial.
        let leaf = CString::new("/var/run/secrets/kubernetes.io/x").unwrap();
        let result =
            unsafe { either_secret_with(leaf.as_ptr(), leaf.as_ptr(), None) };
        assert!(!result);
    }

    // ---- derived constants ------------------------------------------------

    #[test]
    fn k8s_secrets_path_is_kubernetes_io_dir() {
        // Pin the default protected directory.
        assert_eq!(K8S_SECRETS_PATH, "/var/run/secrets/kubernetes.io");
    }

    #[test]
    fn k8s_secrets_path_has_no_trailing_slash() {
        // Stylistic invariant: directory paths in this crate are stored
        // without a trailing slash so canonicalize results compare cleanly.
        assert!(!K8S_SECRETS_PATH.ends_with('/'));
    }
}
