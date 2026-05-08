//! `hook!` and `real!` macros for libc interposition.
//!
//! Linux: lazy `dlsym(RTLD_NEXT)`; missing symbols return `ENOSYS`.
//! macOS: `__DATA,__interpose` entries resolved by dyld at load time.

#[cfg(target_os = "linux")]
use libc::{c_char, c_void};

/// Resolves `symbol` via `dlsym(RTLD_NEXT, ...)`. Null if absent.
///
/// # Safety
/// `symbol` must be NUL-terminated.
#[cfg(target_os = "linux")]
pub(crate) unsafe fn dlsym_next(symbol: &'static str) -> *const u8 {
    // libc::RTLD_NEXT is not guaranteed across libc targets.
    const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;
    unsafe {
        libc::dlsym(RTLD_NEXT, symbol.as_ptr() as *const c_char) as *const u8
    }
}

/// Warns to stderr that a libc symbol failed to resolve.
#[cfg(target_os = "linux")]
pub(crate) fn warn_missing_symbol(symbol_with_nul: &'static str) {
    use std::io::Write;
    let name =
        symbol_with_nul.strip_suffix('\0').unwrap_or(symbol_with_nul);
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(b"secretbro: dlsym(RTLD_NEXT, \"");
    let _ = err.write_all(name.as_bytes());
    let _ = err.write_all(
        b"\") returned null; calls fall back to errno=ENOSYS\n",
    );
}

/// Libc error sentinel per return type, for the ENOSYS fallback.
#[cfg(target_os = "linux")]
pub(crate) trait HookSentinel: Sized {
    fn sentinel() -> Self;
}

#[cfg(target_os = "linux")]
impl HookSentinel for i32 {
    #[inline]
    fn sentinel() -> Self {
        -1
    }
}

#[cfg(target_os = "linux")]
impl HookSentinel for isize {
    #[inline]
    fn sentinel() -> Self {
        -1
    }
}

#[cfg(target_os = "linux")]
impl<T> HookSentinel for *mut T {
    #[inline]
    fn sentinel() -> Self {
        ::std::ptr::null_mut()
    }
}

#[cfg(target_os = "linux")]
macro_rules! hook {
    (unsafe fn $real_fn:ident ( $($v:ident : $t:ty),* ) -> $r:ty
                              => $hook_fn:ident $body:block) => {
        // Load-bearing field: a unit struct would shadow the static below.
        #[allow(non_camel_case_types)]
        struct $real_fn {
            __private_field: (),
        }
        #[allow(non_upper_case_globals)]
        static $real_fn: $real_fn = $real_fn { __private_field: () };

        impl $real_fn {
            // Stub for unresolved libc symbol: errno=ENOSYS + sentinel.
            #[allow(unused_variables)]
            unsafe extern "C" fn __enosys_fallback(
                $($v: $t),*
            ) -> $r {
                unsafe {
                    *$crate::get_errno() = ::libc::ENOSYS;
                }
                <$r as $crate::hook::HookSentinel>::sentinel()
            }

            #[inline]
            fn get(&self) -> unsafe extern "C" fn($($v: $t),*) -> $r {
                static REAL: ::std::sync::OnceLock<
                    unsafe extern "C" fn($($v: $t),*) -> $r,
                > = ::std::sync::OnceLock::new();
                *REAL.get_or_init(|| {
                    let sym = concat!(stringify!($real_fn), "\0");
                    let p = unsafe { $crate::hook::dlsym_next(sym) };
                    if p.is_null() {
                        $crate::hook::warn_missing_symbol(sym);
                        Self::__enosys_fallback
                    } else {
                        unsafe { ::std::mem::transmute(p) }
                    }
                })
            }

            #[no_mangle]
            pub unsafe extern "C" fn $real_fn(
                $($v: $t),*
            ) -> $r {
                $hook_fn($($v),*)
            }
        }

        unsafe fn $hook_fn($($v: $t),*) -> $r $body
    };
}

#[cfg(target_os = "macos")]
macro_rules! hook {
    (unsafe fn $real_fn:ident ( $($v:ident : $t:ty),* ) -> $r:ty
                              => $hook_fn:ident $body:block) => {
        #[allow(non_snake_case)]
        mod $real_fn {
            #[repr(C)]
            pub struct Interpose {
                _new: *const (),
                _old: *const (),
            }
            // SAFETY: read-only after dyld processes the section.
            unsafe impl Sync for Interpose {}

            #[link_section = "__DATA,__interpose"]
            #[used]
            pub static __INTERPOSE: Interpose = Interpose {
                _new: super::$hook_fn as *const (),
                _old: super::$real_fn as *const (),
            };
        }

        extern "C" {
            fn $real_fn($($v: $t),*) -> $r;
        }

        #[allow(dead_code)]
        unsafe extern "C" fn $hook_fn($($v: $t),*) -> $r $body
    };
}

#[cfg(target_os = "linux")]
macro_rules! real {
    ($real_fn:ident) => {
        $real_fn.get()
    };
}

#[cfg(target_os = "macos")]
macro_rules! real {
    ($real_fn:ident) => {
        $real_fn
    };
}
