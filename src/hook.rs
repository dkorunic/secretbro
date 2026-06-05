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

/// Pure I/O form of `warn_missing_symbol`, for unit tests.
#[cfg(target_os = "linux")]
fn write_missing_symbol_message(
    writer: &mut impl std::io::Write,
    symbol_with_nul: &str,
) -> std::io::Result<()> {
    let name = symbol_with_nul.strip_suffix('\0').unwrap_or(symbol_with_nul);
    writer.write_all(b"secretbro: dlsym(RTLD_NEXT, \"")?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(b"\") returned null; calls fall back to errno=ENOSYS\n")
}

/// Warns to stderr that a libc symbol failed to resolve.
#[cfg(target_os = "linux")]
pub(crate) fn warn_missing_symbol(symbol_with_nul: &'static str) {
    let mut err = std::io::stderr().lock();
    let _ = write_missing_symbol_message(&mut err, symbol_with_nul);
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
        #[expect(non_camel_case_types)]
        struct $real_fn {
            __private_field: (),
        }
        #[expect(non_upper_case_globals)]
        static $real_fn: $real_fn = $real_fn { __private_field: () };

        impl $real_fn {
            // Stub for unresolved libc symbol: errno=ENOSYS + sentinel.
            // Params are intentionally unused (we only set errno + return).
            #[expect(unused_variables)]
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
                        unsafe {
                            ::std::mem::transmute::<
                                *const u8,
                                unsafe extern "C" fn($($v: $t),*) -> $r,
                            >(p)
                        }
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

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    // Dispatch fixture skips `real!()`; macro static + get() unused.
    #![expect(dead_code)]

    use libc::c_int;

    use super::*;

    // ---- HookSentinel ----------------------------------------------------

    #[test]
    fn hook_sentinel_i32_is_minus_one() {
        assert_eq!(<i32 as HookSentinel>::sentinel(), -1_i32);
    }

    #[test]
    fn hook_sentinel_isize_is_minus_one() {
        assert_eq!(<isize as HookSentinel>::sentinel(), -1_isize);
    }

    #[test]
    fn hook_sentinel_pointer_is_null() {
        let p: *mut u8 = HookSentinel::sentinel();
        assert!(p.is_null());
        let p: *mut libc::FILE = HookSentinel::sentinel();
        assert!(p.is_null());
        let p: *mut libc::DIR = HookSentinel::sentinel();
        assert!(p.is_null());
    }

    // ---- dlsym_next ------------------------------------------------------

    #[test]
    fn dlsym_next_resolves_known_libc_symbol() {
        let p = unsafe { dlsym_next("getpid\0") };
        assert!(!p.is_null(), "RTLD_NEXT failed to resolve getpid");
    }

    #[test]
    fn dlsym_next_returns_null_for_unknown_symbol() {
        let p =
            unsafe { dlsym_next("__secretbro_test_missing_symbol_q1z9k\0") };
        assert!(p.is_null());
    }

    // ---- write_missing_symbol_message -----------------------------------

    #[test]
    fn write_missing_symbol_message_strips_trailing_nul() {
        let mut buf = Vec::new();
        write_missing_symbol_message(&mut buf, "open\0").unwrap();
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("\"open\""), "got {s:?}");
        assert!(!s.contains('\0'));
    }

    #[test]
    fn write_missing_symbol_message_full_format() {
        // Wire format is operator-facing; changes should be deliberate.
        let mut buf = Vec::new();
        write_missing_symbol_message(&mut buf, "stat\0").unwrap();
        assert_eq!(
            std::str::from_utf8(&buf).unwrap(),
            "secretbro: dlsym(RTLD_NEXT, \"stat\") returned null; \
             calls fall back to errno=ENOSYS\n"
        );
    }

    #[test]
    fn write_missing_symbol_message_no_trailing_nul_passthrough() {
        let mut buf = Vec::new();
        write_missing_symbol_message(&mut buf, "raw").unwrap();
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("\"raw\""));
    }

    // ---- hook! macro -----------------------------------------------------
    // Unique names: `#[no_mangle]` must not collide; RTLD_NEXT must miss.

    hook! {
        unsafe fn secretbro_test_dispatch_q1z9k(x: c_int) -> c_int
            => my_test_dispatch
        {
            x.wrapping_add(100)
        }
    }

    #[test]
    fn hook_macro_dispatches_wrapper_to_hook_body() {
        // `Type::Type` is the export hung on the marker struct.
        let r = unsafe {
            secretbro_test_dispatch_q1z9k::secretbro_test_dispatch_q1z9k(7)
        };
        assert_eq!(r, 107);
    }

    hook! {
        unsafe fn secretbro_test_enosys_q1z9k(x: c_int) -> c_int
            => my_test_enosys
        {
            unsafe { real!(secretbro_test_enosys_q1z9k)(x) }
        }
    }

    #[test]
    fn hook_macro_falls_back_to_enosys_when_real_missing() {
        // RTLD_NEXT misses → ENOSYS stub fires.
        unsafe {
            *crate::get_errno() = 0;
            let r =
                secretbro_test_enosys_q1z9k::secretbro_test_enosys_q1z9k(42);
            assert_eq!(r, -1);
            assert_eq!(*crate::get_errno(), libc::ENOSYS);
        }
    }

    hook! {
        unsafe fn secretbro_test_enosys_ssize_q1z9k(x: c_int) -> isize
            => my_test_enosys_ssize
        {
            unsafe { real!(secretbro_test_enosys_ssize_q1z9k)(x) }
        }
    }

    #[test]
    fn hook_macro_enosys_returns_minus_one_for_ssize() {
        unsafe {
            *crate::get_errno() = 0;
            let r = secretbro_test_enosys_ssize_q1z9k::secretbro_test_enosys_ssize_q1z9k(0);
            assert_eq!(r, -1isize);
            assert_eq!(*crate::get_errno(), libc::ENOSYS);
        }
    }

    hook! {
        unsafe fn secretbro_test_enosys_ptr_q1z9k(x: c_int) -> *mut libc::FILE
            => my_test_enosys_ptr
        {
            unsafe { real!(secretbro_test_enosys_ptr_q1z9k)(x) }
        }
    }

    #[test]
    fn hook_macro_enosys_returns_null_for_pointer() {
        unsafe {
            *crate::get_errno() = 0;
            let r = secretbro_test_enosys_ptr_q1z9k::secretbro_test_enosys_ptr_q1z9k(0);
            assert!(r.is_null());
            assert_eq!(*crate::get_errno(), libc::ENOSYS);
        }
    }
}
