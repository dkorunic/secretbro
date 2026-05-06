#[cfg(all(target_os = "linux", target_env = "gnu"))]
use libc::c_uint;
use libc::{DIR, FILE, c_char, c_int, mode_t, size_t, ssize_t};
use redhook::{hook, real};
use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::LazyLock;

/// FFI mirror of Linux's `struct file_handle`.
///
/// Only used to type the `name_to_handle_at` hook signature; the body never
/// reads or writes the fields, just forwards the pointer to the real libc.
/// Layout matches the kernel struct so future edits don't read garbage.
#[repr(C)]
#[allow(non_snake_case)]
pub struct file_handle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; 0],
}

const K8S_SECRETS_PATH: &str = "/var/run/secrets/kubernetes.io";

/// Bytes view of `K8S_SECRETS_PATH`. `&str::as_bytes` is `const fn`, so this
/// is materialized at compile time and avoids an `as_bytes()` call per hook.
const K8S_SECRETS_PATH_BYTES: &[u8] = K8S_SECRETS_PATH.as_bytes();

/// Canonicalized absolute path of the protected secrets directory.
///
/// `None` if the directory is missing or cannot be canonicalized; in that
/// state the library is a no-op (every hook calls through). Avoids aborting
/// host processes outside Kubernetes pods, since the release profile uses
/// `panic = "abort"`.
///
/// The path source can be overridden via `SECRETBRO_PATH`, read once at
/// first hook invocation.
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

/// `slice::starts_with` extended to require a `/` (or end-of-string) after
/// the prefix, so e.g. `/var/run/secrets/kubernetes.iox` does not match
/// `/var/run/secrets/kubernetes.io`.
fn path_has_prefix(path: &[u8], prefix: &[u8]) -> bool {
    path.starts_with(prefix)
        && (path.len() == prefix.len() || path[prefix.len()] == b'/')
}

/// True if `bytes` is an absolute path with no redundant components
/// (`//`, `/./`, `/../`) so that lexical prefix comparison gives the same
/// answer as `realpath`. Used to gate the fast-path safely.
fn is_simple_absolute(bytes: &[u8]) -> bool {
    bytes.first() == Some(&b'/')
        && !bytes.windows(2).any(|w| w == b"//")
        && !bytes.windows(3).any(|w| w == b"/./")
        && !bytes.windows(4).any(|w| w == b"/../")
        && !bytes.ends_with(b"/.")
        && !bytes.ends_with(b"/..")
}

/// Pure decision logic for whether a path resolves into `secrets`.
///
/// `pathname_bytes` is the raw input path as the libc caller supplied it.
/// `secrets` is an already-canonicalized directory.
/// `text_prefix` is an additional textual prefix used by the fast-path —
/// typically the original (unresolved) `K8S_SECRETS_PATH` constant, so that
/// callers who name the directory by its symlink form still hit the slow
/// path. Pass `secrets` again if no second prefix is needed.
///
/// "Indeterminate" inputs — empty path, or a path whose canonical form
/// cannot be computed even via its parent — return `false`. This function
/// adds deny rules to a subset of paths and must not break unrelated I/O.
fn is_path_under_secrets(
    pathname_bytes: &[u8],
    secrets: &Path,
    text_prefix: &[u8],
) -> bool {
    if pathname_bytes.is_empty() {
        return false;
    }

    // Fast-allow: a normalized absolute path whose textual form does not
    // begin with the configured prefix or its canonical form cannot resolve
    // into the secrets directory short of an external symlink redirecting
    // into it. Skipping `realpath` for this 99% case is the main perf win.
    //
    // When `text_prefix == secrets_bytes` (the default config, no symlink
    // redirection), the second `path_has_prefix` would compute the same
    // result as the first; short-circuit on slice equality to skip it.
    let secrets_bytes = secrets.as_os_str().as_bytes();
    if is_simple_absolute(pathname_bytes)
        && !path_has_prefix(pathname_bytes, text_prefix)
        && (text_prefix == secrets_bytes
            || !path_has_prefix(pathname_bytes, secrets_bytes))
    {
        return false;
    }

    // Linux paths are arbitrary bytes; round-tripping through `to_string_lossy`
    // would corrupt non-UTF8 components and silently mismatch the path libc
    // sees. Use the raw bytes instead.
    let path = Path::new(OsStr::from_bytes(pathname_bytes));

    let canonical = match path.canonicalize() {
        Ok(p) => p,
        // Leaf doesn't exist (e.g. `creat()` of a new file). Resolve the
        // parent and re-attach the leaf so creates targeting the secrets
        // directory are still detected. Without this, every file creation
        // anywhere would be incorrectly denied.
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

/// Returns true iff `pathname` resolves into the protected secrets
/// directory. On true, `errno = EACCES` is set so the caller can return the
/// libc error sentinel without further setup.
///
/// "Indeterminate" inputs — null pointer, empty path, secrets directory not
/// configured at startup, or a path whose canonical form cannot be computed
/// even via its parent — are treated as *not* a secret. This library adds
/// deny rules to a subset of paths and must not break unrelated I/O; the
/// real libc call still produces a natural error (e.g. ENOENT) when the
/// path is genuinely invalid.
///
/// Limitations:
///   - TOCTOU between this check and the real syscall is unavoidable for
///     path-based interposition; a racing symlink edit can bypass the
///     control. Out of scope for this library.
///   - The lexical fast-path assumes no symlink outside the secrets
///     directory redirects into it — which holds for typical Kubernetes
///     pod filesystems and matches the threat model in README.md.
///
/// # Safety
/// `pathname` must be NULL or point to a NUL-terminated C string.
unsafe fn is_secret_path(pathname: *const c_char) -> bool {
    unsafe { is_secret_path_with(pathname, K8S_SECRETS.as_deref()) }
}

/// Inner form of `is_secret_path` that takes the secrets directory as an
/// explicit argument so the `K8S_SECRETS == None` branch is unit-testable
/// without depending on the global `LazyLock`.
///
/// # Safety
/// `pathname` must be NULL or point to a NUL-terminated C string.
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

    if is_path_under_secrets(bytes, secrets, K8S_SECRETS_PATH_BYTES) {
        unsafe { get_errno().write(libc::EACCES) };
        true
    } else {
        false
    }
}

/// Returns true iff *either* path resolves into the secrets directory.
/// Used by two-path operations (rename, link, symlink, *at variants).
///
/// # Safety
/// Both pointers must be NULL or point to NUL-terminated C strings.
unsafe fn either_secret(p1: *const c_char, p2: *const c_char) -> bool {
    unsafe { is_secret_path(p1) || is_secret_path(p2) }
}

// ---------------------------------------------------------------------------
// Hooks
//
// Variadic ABI note: `open(2)`, `openat(2)`, and their `*64` LFS variants
// are variadic in C — `mode_t` is read only when `O_CREAT` / `O_TMPFILE` is
// in `flags`. `redhook::hook!` cannot describe varargs, so we declare
// `mode_t` as a fixed argument. On AMD64 SysV and AArch64 AAPCS, callers
// that omit `mode` simply leave the corresponding register undefined; the
// hook reads it and forwards it to the real libc, which discards it when
// `O_CREAT` is absent. Benign on these ABIs but a strict ABI mismatch.
//
// `creat(path, mode_t)`, `fopen(path, *const c_char)`, and the modify
// operations below are NOT variadic — their declarations match libc
// exactly.
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

/* int access(const char *pathname, int mode); */
hook! {
    unsafe fn access(pathname: *const c_char, mode: c_int) -> c_int => my_access {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(access)(pathname, mode)
            }
        }
    }
}

/* ssize_t readlink(const char *pathname, char *buf, size_t bufsiz); */
hook! {
    unsafe fn readlink(pathname: *const c_char, buf: *mut c_char, bufsiz: size_t) -> ssize_t => my_readlink {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(readlink)(pathname, buf, bufsiz)
            }
        }
    }
}

/* DIR *opendir(const char *name); */
hook! {
    unsafe fn opendir(name: *const c_char) -> *mut DIR => my_opendir {
        unsafe {
            if is_secret_path(name) {
                null_mut()
            } else {
                real!(opendir)(name)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-platform modify hooks
//
// Block creation, deletion, and metadata mutation of paths inside the
// secrets directory. Two-path operations (`rename`, `link`, `symlink`)
// deny if *either* path is in secrets, so an attacker cannot move a
// secret out or shadow it with a new entry.
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

// stat / lstat / fstatat / *at variants are Linux-gated because on x86_64
// macOS the real symbols are mangled (`stat$INODE64`, etc.); a plain `stat`
// hook there would not intercept calls. Linux has no such mangling.

/* int stat(const char *pathname, struct stat *statbuf); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn stat(pathname: *const c_char, buf: *mut libc::stat) -> c_int => my_stat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(stat)(pathname, buf)
            }
        }
    }
}

/* int lstat(const char *pathname, struct stat *statbuf); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn lstat(pathname: *const c_char, buf: *mut libc::stat) -> c_int => my_lstat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(lstat)(pathname, buf)
            }
        }
    }
}

/* int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn fstatat(dirfd: c_int, pathname: *const c_char, buf: *mut libc::stat, flags: c_int) -> c_int => my_fstatat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(fstatat)(dirfd, pathname, buf, flags)
            }
        }
    }
}

/* int faccessat(int dirfd, const char *pathname, int mode, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn faccessat(dirfd: c_int, pathname: *const c_char, mode: c_int, flags: c_int) -> c_int => my_faccessat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(faccessat)(dirfd, pathname, mode, flags)
            }
        }
    }
}

/* ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn readlinkat(dirfd: c_int, pathname: *const c_char, buf: *mut c_char, bufsiz: size_t) -> ssize_t => my_readlinkat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(readlinkat)(dirfd, pathname, buf, bufsiz)
            }
        }
    }
}

/* int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags); */
#[cfg(target_os = "linux")]
hook! {
    unsafe fn name_to_handle_at(dirfd: c_int, pathname: *const c_char, handle: *mut file_handle, mount_id: *mut c_int, flags: c_int) -> c_int => my_name_to_handle_at {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(name_to_handle_at)(dirfd, pathname, handle, mount_id, flags)
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

/* int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn statx(dirfd: c_int, pathname: *const c_char, flags: c_int, mask: c_uint, statxbuf: *mut libc::statx) -> c_int => my_statx {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(statx)(dirfd, pathname, flags, mask, statxbuf)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// glibc Linux LFS variants
//
// The `*64` symbols are a glibc convention for explicit 64-bit `off_t`; they
// don't exist on musl libc (which has 64-bit `off_t` natively) or on macOS.
// The previous `target_arch = "x86_64"` gate was wrong on both axes:
// aarch64-gnu builds missed them, and x86_64-musl builds exported dead
// symbols.
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

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn stat64(pathname: *const c_char, buf: *mut libc::stat64) -> c_int => my_stat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(stat64)(pathname, buf)
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn lstat64(pathname: *const c_char, buf: *mut libc::stat64) -> c_int => my_lstat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(lstat64)(pathname, buf)
            }
        }
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn fstatat64(dirfd: c_int, pathname: *const c_char, buf: *mut libc::stat64, flags: c_int) -> c_int => my_fstatat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(fstatat64)(dirfd, pathname, buf, flags)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// glibc Linux modify variants
//
// `truncate64` is the explicit-64-bit-`off_t` variant of `truncate`, like
// the LFS read variants above. `renameat2` is glibc-specific (added in
// glibc 2.28; the syscall itself is Linux-only).
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

// ---------------------------------------------------------------------------
// glibc stat-versioning compatibility shims (`__xstat` family)
//
// glibc < 2.33 routed `stat`/`lstat`/`fstatat` through versioned wrappers
// `__xstat`/`__lxstat`/`__fxstatat` that take a leading `int ver` argument
// (the layout version of `struct stat`). Modern glibc (≥ 2.33, Feb 2021)
// emits direct `stat`/`lstat`/`fstatat` symbols, but the versioned ones are
// still exported as compatibility stubs. Hook both so binaries built
// against older glibc are also intercepted.
//
// `dlsym(RTLD_NEXT, "__xstat")` is performed lazily by `redhook`'s `real!`,
// so the hook is harmless on systems that don't export the symbol — it
// simply never fires there.
// ---------------------------------------------------------------------------

/* int __xstat(int ver, const char *path, struct stat *buf); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn __xstat(ver: c_int, pathname: *const c_char, buf: *mut libc::stat) -> c_int => my_xstat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(__xstat)(ver, pathname, buf)
            }
        }
    }
}

/* int __lxstat(int ver, const char *path, struct stat *buf); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn __lxstat(ver: c_int, pathname: *const c_char, buf: *mut libc::stat) -> c_int => my_lxstat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(__lxstat)(ver, pathname, buf)
            }
        }
    }
}

/* int __fxstatat(int ver, int dirfd, const char *path, struct stat *buf, int flags); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn __fxstatat(ver: c_int, dirfd: c_int, pathname: *const c_char, buf: *mut libc::stat, flags: c_int) -> c_int => my_fxstatat {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(__fxstatat)(ver, dirfd, pathname, buf, flags)
            }
        }
    }
}

/* int __xstat64(int ver, const char *path, struct stat64 *buf); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn __xstat64(ver: c_int, pathname: *const c_char, buf: *mut libc::stat64) -> c_int => my_xstat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(__xstat64)(ver, pathname, buf)
            }
        }
    }
}

/* int __lxstat64(int ver, const char *path, struct stat64 *buf); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn __lxstat64(ver: c_int, pathname: *const c_char, buf: *mut libc::stat64) -> c_int => my_lxstat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(__lxstat64)(ver, pathname, buf)
            }
        }
    }
}

/* int __fxstatat64(int ver, int dirfd, const char *path, struct stat64 *buf, int flags); */
#[cfg(all(target_os = "linux", target_env = "gnu"))]
hook! {
    unsafe fn __fxstatat64(ver: c_int, dirfd: c_int, pathname: *const c_char, buf: *mut libc::stat64, flags: c_int) -> c_int => my_fxstatat64 {
        unsafe {
            if is_secret_path(pathname) {
                -1
            } else {
                real!(__fxstatat64)(ver, dirfd, pathname, buf, flags)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // ---- helpers ---------------------------------------------------------

    /// One-shot temp directory rooted at `std::env::temp_dir()`. Avoids the
    /// `tempfile` dev-dependency. Removed on `Drop`. Path is canonicalized
    /// up front so comparisons aren't tripped up by `/tmp -> /private/tmp`
    /// (macOS) or other temp-root symlinks.
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
        is_path_under_secrets(
            path_bytes,
            secrets,
            secrets.as_os_str().as_bytes(),
        )
    }

    // ---- path_has_prefix --------------------------------------------------

    #[test]
    fn path_has_prefix_requires_separator() {
        let p = b"/var/run/secrets/kubernetes.io";
        assert!(path_has_prefix(p, p));
        assert!(path_has_prefix(b"/var/run/secrets/kubernetes.io/x", p));
        // Sibling directory whose name extends the prefix must not match.
        assert!(!path_has_prefix(b"/var/run/secrets/kubernetes.iox", p));
        assert!(!path_has_prefix(b"/var/run", p));
    }

    #[test]
    fn path_has_prefix_edge_cases() {
        // Empty prefix matches everything (including empty).
        assert!(path_has_prefix(b"", b""));
        assert!(path_has_prefix(b"/foo", b""));
        // Prefix longer than path cannot match.
        assert!(!path_has_prefix(b"/a", b"/abc"));
        // Empty path with non-empty prefix.
        assert!(!path_has_prefix(b"", b"/a"));
        // Prefix `/` matches itself but not `/a`: the boundary check
        // requires a `/` (or end-of-string) immediately after the prefix.
        // Production never passes `/` as a prefix, but documenting the
        // semantics here prevents future regressions.
        assert!(path_has_prefix(b"/", b"/"));
        assert!(!path_has_prefix(b"/a", b"/"));
    }

    // ---- is_simple_absolute ----------------------------------------------

    #[test]
    fn is_simple_absolute_rejects_traversal() {
        assert!(is_simple_absolute(b"/etc/passwd"));
        assert!(is_simple_absolute(b"/var/run/secrets/kubernetes.io/x"));
        assert!(!is_simple_absolute(b"etc/passwd"));
        assert!(!is_simple_absolute(b"//etc/passwd"));
        assert!(!is_simple_absolute(b"/etc/./passwd"));
        assert!(!is_simple_absolute(b"/etc/../etc/passwd"));
        assert!(!is_simple_absolute(b"/etc/."));
        assert!(!is_simple_absolute(b"/etc/.."));
        // hidden filenames are still simple
        assert!(is_simple_absolute(b"/home/user/.bashrc"));
    }

    #[test]
    fn is_simple_absolute_more_edges() {
        assert!(!is_simple_absolute(b""));
        assert!(is_simple_absolute(b"/"));
        // Trailing slash is fine; not a redundant component.
        assert!(is_simple_absolute(b"/etc/"));
        // `..` or `.` only count as a component, not as a substring.
        assert!(is_simple_absolute(b"/etc/..foo"));
        assert!(is_simple_absolute(b"/etc/.foo"));
        assert!(is_simple_absolute(b"/foo..bar"));
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
        // `<root>/secretsx/...` shares a textual prefix with `<root>/secrets`
        // but is a different directory. The separator check in
        // `path_has_prefix` must reject this.
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
    fn under_secrets_double_slash_forces_canonicalize() {
        // `//` disqualifies the lexical fast-path; the slow path must still
        // detect the secrets prefix.
        let t = TempDir::new("double-slash");
        let s = make_secrets(&t);
        let leaf = s.join("token");
        std::fs::write(&leaf, b"x").unwrap();
        let weird = format!("{}//token", s.as_os_str().to_str().unwrap());
        assert!(check(weird.as_bytes(), &s));
    }

    #[test]
    fn under_secrets_text_prefix_when_canonical_differs() {
        // Caller names the directory by its textual K8S prefix even though
        // the configured `secrets` is a different canonical path. The
        // textual fast-path must not short-circuit; the slow path then
        // returns false because canonical doesn't match.
        let t = TempDir::new("text-prefix");
        let s = make_secrets(&t);
        let textual = b"/var/run/secrets/kubernetes.io/token";
        // Use the real K8S constant as the text prefix.
        let result =
            is_path_under_secrets(textual, &s, K8S_SECRETS_PATH.as_bytes());
        // Path doesn't actually exist on this test host, so canonicalize
        // and parent-canonicalize both fail → false (indeterminate).
        assert!(!result);
    }

    #[test]
    fn under_secrets_relative_path_is_indeterminate() {
        let t = TempDir::new("relative");
        let s = make_secrets(&t);
        // Relative paths bypass the fast-path (not absolute) and then fail
        // canonicalization since the leaf doesn't exist in cwd.
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
        // Exercises the explicit None branch: when the secrets directory
        // was missing or unresolvable at startup, the wrapper must return
        // false for every input without setting errno (library no-op
        // mode).
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
}
