# Remove `redhook` dependency by inlining its macros

**Date:** 2026-05-08
**Status:** Approved
**Author:** Dinko Korunic (with Claude Code)

## Summary

`secretbro` currently depends on `redhook` 2.0.0 (last released 2017, unmaintained) for the `hook!` and `real!` macros that generate libc-interposition shims. The dependency has two costs:

1. `redhook` gates its Linux LD_PRELOAD path on `target_env = "gnu"`, so `cargo build --target x86_64-unknown-linux-musl` fails at macro-expansion time even though `dist-workspace.toml` lists musl as a release target.
2. `redhook`'s implementation uses `Once + static mut REAL`, which is a deprecated pattern in modern Rust and produces lints in newer compilers.

This change inlines an equivalent (but slimmer and modernized) version of `hook!` / `real!` directly into the project, then drops the `redhook` crate from `Cargo.toml`.

## Behavior contract

The libc-interposition behavior must be identical before and after this change:

- Same set of `#[no_mangle] extern "C"` symbols exported on Linux (every `hook! { ... }` site in `src/lib.rs`).
- Same Mach-O `__DATA,__interpose` entries on macOS.
- Same lazy-resolved `dlsym(RTLD_NEXT, "name\0")` for the real libc fall-through on Linux.
- No change to the path-decision logic (`is_secret_path`, `is_path_under_secrets`, etc.) or the unit tests that exercise it.

The only externally visible change is positive: `cargo build --target x86_64-unknown-linux-musl` becomes a working command.

## Non-goals

- No new hooked syscalls.
- No change to the threat model, errno strategy, or fast-path optimization.
- No change to the public Rust API (the crate exposes none — it's a `cdylib`).
- No removal or replacement of `libc` (still required for the type definitions).

## Architecture

### New file: `src/hook.rs`

Contains:

1. `dlsym_next(symbol: &'static str) -> *const u8` — resolves a libc symbol via `libc::dlsym(libc::RTLD_NEXT, ...)`. On null result, writes a stderr message and aborts (matches the `redhook` "panic on failure" semantics, but explicit `process::abort()` since `panic = "abort"` collapses panics into aborts anyway).

2. **`hook!` macro for Linux** (any libc, including musl). Per invocation, expands to:
   - `pub struct $real_fn { _private: () }` plus a unit static of that name (occupies the type and value namespaces under the same identifier — same trick as upstream `redhook`).
   - `impl $real_fn { fn get(&self) -> unsafe extern "C" fn(...) -> ... }` — uses a function-local `OnceLock<unsafe extern "C" fn(...) -> ...>` to cache the dlsym result. Function pointers are `Sync` so no `unsafe impl` is needed (improvement over the upstream `static mut REAL`).
   - `impl $real_fn { #[no_mangle] pub unsafe extern "C" fn $real_fn(...) -> ... { $hook_fn(...) } }` — the exported symbol. Body just delegates to the user-supplied hook function.
   - `unsafe fn $hook_fn(...) -> ... $body` — the user-supplied hook body. References `real!(name)` to call through to libc.

3. **`hook!` macro for macOS**. Per invocation, expands to:
   - A submodule containing a `#[link_section = "__DATA,__interpose"] #[used] static` whose value is `(hook_fn as *const (), real_fn as *const ())`. The static type carries `unsafe impl Sync` (improvement over upstream `static mut`).
   - `extern "C" { pub fn $real_fn(...) -> ...; }` — declaration of the libc symbol (callable from inside our cdylib without redirection).
   - `pub unsafe extern "C" fn $hook_fn(...) -> ... { $body }` — the user-supplied hook function. The interposer's `_new` field points here; dyld redirects external calls.

4. **`real!` macro**:
   - Linux: expands to `$real_fn.get()` — calls `get()` on the static, returning a fn pointer.
   - macOS: expands to `$real_fn` — references the extern decl.

The macros are not `#[macro_export]`-ed; they're crate-internal. lib.rs uses them via `#[macro_use] mod hook;`.

### Differences from upstream `redhook`

| Aspect | Upstream `redhook` 2.0.0 | This implementation |
|---|---|---|
| Linux libc gate | `#[cfg(target_env = "gnu")]` | None — works on glibc and musl |
| dlsym cache | `Once + static mut REAL: *const u8` | `OnceLock<unsafe extern "C" fn(...)>` |
| Panic handling | `catch_unwind` around hook body, falls back to real on unwind | None — `panic = "abort"` makes catch_unwind dead code |
| ABI on hook fn | `unsafe extern fn` (defaults to `"C"`) | `unsafe extern "C" fn` (explicit) |
| `#[link(name = "dl")]` | Yes, manually declared | Uses `libc::dlsym` (libc crate handles linkage) |
| macOS interpose static | `pub static mut` | `pub static` + `unsafe impl Sync` |

### Files changed

| Path | Change |
|---|---|
| `src/hook.rs` | New file. ~80 lines. |
| `src/lib.rs` | `use redhook::{hook, real};` → `#[macro_use] mod hook;`. No other changes. |
| `Cargo.toml` | Remove `redhook = "2.0.0"`. |
| `Cargo.lock` | Updated by cargo. |
| `CLAUDE.md` | Revise: drop the "redhook is unmaintained" and "cannot build for musl" notes; update file-layout note from "everything lives in `src/lib.rs`" to mention `src/hook.rs`. |

## Verification plan

1. **Unit tests:** `cargo test` — must continue to pass. The tests exercise `is_path_under_secrets` and friends, which have no dependency on the macro layer.
2. **Local release build:** `cargo build --release` on macOS host — must produce `target/release/libsecretbro.dylib` with no new warnings. Verify `nm` shows the same exported symbol set as before.
3. **Lints:** `cargo clippy --release --all-targets` — clean.
4. **Linux GNU cross-check (if available):** `cargo check --target x86_64-unknown-linux-gnu`.
5. **Linux musl** (the new capability): `cargo check --target x86_64-unknown-linux-musl`. This must succeed at the macro/type level. If linker errors arise from a missing musl cross linker, that's an environment issue (out of scope), not a code issue — note it but don't block on it.

## Risks

- **Macro hygiene around `$crate`:** the new macros reference `$crate::hook::dlsym_next`, where `$crate` resolves to `secretbro` itself. Risk is low — the macros are defined and used in the same crate; `$crate` is the standard mechanism for this.
- **`#[no_mangle]` on inherent methods:** still allowed in edition 2021 (no `#[unsafe(no_mangle)]` requirement); confirm no warning fires on the toolchain in `rust-toolchain.toml`.
- **`OnceLock<fn ptr>`:** stabilized in Rust 1.70; MSRV in `Cargo.toml` is 1.80.1. Comfortable margin.
- **`extern "C" fn(...)` is `Sync`:** documented in std but worth noting — this is what allows us to drop the `static mut` pattern.
- **Per-hook code-size cost:** each `OnceLock<fn ptr>` is ~16 bytes BSS plus a single-shot init closure. For ~50 hooks that's ~800 bytes, negligible vs. the dylib's text segment.

## Out of scope (revisit separately)

- Replacing `libc` with hand-rolled FFI declarations.
- Adding hook coverage for additional syscalls (`statfs`, `getxattr`, etc.).
- Changing the canonicalization strategy in `is_path_under_secrets`.
