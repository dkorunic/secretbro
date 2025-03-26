use libc::{FILE, c_char, c_int, mode_t};
use redhook::{hook, real};
use std::ffi::CStr;
use std::ptr::null_mut;

const K8S_SECRETS: &str = "/var/run/secrets/kubernetes.io";

/* int creat(const char *pathname, mode_t mode); */
hook! {
    unsafe fn creat(pathname: *const c_char, mode: mode_t) -> c_int => my_creat {
        if is_secret_path(pathname) { return -1; }

        unsafe { real!(creat)(pathname, mode) }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn creat64(pathname: *const c_char, mode: mode_t) -> c_int => my_creat64 {
        if is_secret_path(pathname) { return -1; };

        unsafe { real!(creat64)(pathname, mode) }
    }
}

/* int open(const char *pathname, int flags, mode_t mode ); */
hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open {
        if is_secret_path(pathname) { return -1; }

        unsafe { real!(open)(pathname, flags, mode) }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn open64(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open64 {
        if is_secret_path(pathname) { return -1; };

        unsafe { real!(open64)(pathname, flags, mode) }
    }
}

/* int openat(int dirfd, const char *pathname, int flags, mode_t mode); */
hook! {
    unsafe fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat {
        if is_secret_path(pathname) { return -1; }

       unsafe { real!(openat)(dirfd, pathname, flags, mode) }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn openat64(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat64 {
        if is_secret_path(pathname) { return -1 };

        unsafe { real!(openat64)(dirfd, pathname, flags, mode) }
    }
}

/* FILE *fopen(const char *path, const char *mode); */
hook! {
    unsafe fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen {
        if is_secret_path(pathname) { return null_mut(); }

        unsafe { real!(fopen)(pathname, mode) }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn fopen64(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen64 {
        if is_secret_path(pathname) { return null_mut(); }

        unsafe { real!(fopen64)(pathname, mode) }
    }
}

/* FILE *freopen(const char *path, const char *mode, FILE *stream); */
hook! {
    unsafe fn freopen(pathname: *const c_char, mode: *const c_char, file: *mut FILE) -> *mut FILE => my_freopen {
        if is_secret_path(pathname) { return null_mut(); }

        unsafe { real!(freopen)(pathname, mode, file) }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn freopen64(pathname: *const c_char, mode: *const c_char, file: *mut FILE) -> *mut FILE => my_freopen64 {
        if is_secret_path(pathname) { return null_mut(); }

        unsafe { real!(freopen64)(pathname, mode, file) }
    }
}

/// Returns a pointer to the current value of errno.
///
/// This function is unsafe as it returns a raw pointer. On macOS, this function
/// returns a pointer to a `c_int` that is not necessarily aligned to the target
/// type, so it is not safe to dereference.
///
/// # Safety
///
/// This function is safe to call as long as the returned pointer is not
/// dereferenced.
unsafe fn get_errno() -> *mut libc::c_int {
    unsafe {
        #[cfg(target_os = "linux")]
        return libc::__errno_location();

        #[cfg(target_os = "macos")]
        return libc::__error();
    }
}

/// Checks whether the given path points to a Kubernetes secret.
///
/// # Arguments
///
/// * `pathname` - A pointer to a C string representing the path to check.
///
/// # Return value
///
/// `true` if the path points to a Kubernetes secret, `false` otherwise.
///
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer.
fn is_secret_path(pathname: *const c_char) -> bool {
    if pathname.is_null() {
        return false;
    }

    let path_str = unsafe { CStr::from_ptr(pathname).to_string_lossy() };

    if path_str.starts_with(K8S_SECRETS) {
        unsafe {
            get_errno().write(libc::EACCES);
        };

        true
    } else {
        false
    }
}
