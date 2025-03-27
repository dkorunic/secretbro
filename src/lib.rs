use libc::{FILE, c_char, c_int, mode_t};
use redhook::{hook, real};
use std::ffi::CStr;
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::ptr::null_mut;

const K8S_SECRETS: &str = "/var/run/secrets/kubernetes.io";

/* int creat(const char *pathname, mode_t mode); */
hook! {
    unsafe fn creat(pathname: *const c_char, mode: mode_t) -> c_int => my_creat {
        unsafe {
            if check_secret_path(pathname).is_err() {
                -1
            } else {
                real!(creat)(pathname, mode)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn creat64(pathname: *const c_char, mode: mode_t) -> c_int => my_creat64 {
        unsafe {
            if check_secret_path(pathname).is_err() {
                -1
            } else {
                real!(creat64)(pathname, mode)
            }
        }
    }
}

/* int open(const char *pathname, int flags, mode_t mode ); */
hook! {
    unsafe fn open(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open {
        unsafe {
            if check_secret_path(pathname).is_err() {
                -1
            } else {
                real!(open)(pathname, flags, mode)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn open64(pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_open64 {
        unsafe {
            if check_secret_path(pathname).is_err() {
                -1
            } else {
                real!(open64)(pathname, flags, mode)
            }
        }
    }
}

/* int openat(int dirfd, const char *pathname, int flags, mode_t mode); */
hook! {
    unsafe fn openat(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat {
        unsafe {
            if check_secret_path(pathname).is_err() {
                -1
            } else {
                real!(openat)(dirfd, pathname, flags, mode)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn openat64(dirfd: c_int, pathname: *const c_char, flags: c_int, mode: mode_t) -> c_int => my_openat64 {
        unsafe {
            if check_secret_path(pathname).is_err() {
                -1
            } else {
                real!(openat64)(dirfd, pathname, flags, mode)
            }
        }
    }
}

/* FILE *fopen(const char *path, const char *mode); */
hook! {
    unsafe fn fopen(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen {
        unsafe {
            if check_secret_path(pathname).is_err() {
                null_mut()
            } else {
                real!(fopen)(pathname, mode)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn fopen64(pathname: *const c_char, mode: *const c_char) -> *mut FILE => my_fopen64 {
        unsafe {
            if check_secret_path(pathname).is_err() {
                    null_mut()
            } else {
                real!(fopen64)(pathname, mode)
            }
        }
    }
}

/* FILE *freopen(const char *path, const char *mode, FILE *stream); */
hook! {
    unsafe fn freopen(pathname: *const c_char, mode: *const c_char, file: *mut FILE) -> *mut FILE => my_freopen {
        unsafe {
            if check_secret_path(pathname).is_err() {
                null_mut()
            } else {
                real!(freopen)(pathname, mode, file)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
hook! {
    unsafe fn freopen64(pathname: *const c_char, mode: *const c_char, file: *mut FILE) -> *mut FILE => my_freopen64 {
        unsafe {
            if check_secret_path(pathname).is_err() {
                null_mut()
            } else {
                real!(freopen64)(pathname, mode, file)
            }
        }
    }
}

/// Returns a pointer to the current value of errno.
unsafe fn get_errno() -> *mut c_int {
    unsafe {
        #[cfg(target_os = "linux")]
        return libc::__errno_location();

        #[cfg(target_os = "macos")]
        return libc::__error();
    }
}

/// Checks if the given pathname is within the Kubernetes secrets directory.
///
/// If the pathname is null, this function returns `Ok(())`. Otherwise, it
/// checks if the pathname starts with the Kubernetes secrets directory,
/// `/var/run/secrets/kubernetes.io`. If it does, it sets the value of errno to
/// `EACCES` and returns `Err(ErrorKind::PermissionDenied)`. Otherwise, it
/// returns `Ok(())`.
///
/// # Safety
///
/// `pathname` must point to a null-terminated C string
unsafe fn check_secret_path(pathname: *const c_char) -> std::io::Result<()> {
    if pathname.is_null() {
        return Ok(());
    }

    let path_str = unsafe { CStr::from_ptr(pathname).to_string_lossy() };

    // Check if the path starts with /var/run/secrets/kubernetes.io
    if Path::new(&path_str.as_ref()).canonicalize()?.starts_with(K8S_SECRETS) {
        unsafe {
            get_errno().write(libc::EACCES);
        };

        Err(Error::from(ErrorKind::PermissionDenied))
    } else {
        Ok(())
    }
}
