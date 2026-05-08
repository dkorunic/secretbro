# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`secretbro` is a `cdylib` interposition library loaded via `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS). It denies filesystem access to the Kubernetes secrets directory (`/var/run/secrets/kubernetes.io`) for the host process, without modifying the host binary or its source. The protected resource defaults to `K8S_SECRETS_PATH` in `src/lib.rs` and can be overridden at process start via the `SECRETBRO_PATH` environment variable (read once on first hook call).

## Build / Run / Format

- `cargo build --release` — produces `target/release/libsecretbro.{so,dylib}`. The release profile is opinionated (LTO=fat, `panic = "abort"`, `codegen-units = 1`, `strip = "symbols"`); debug builds will work for development but won't match what ships.
- `cargo fmt` — `rustfmt.toml` enforces `max_width = 79` and `use_small_heuristics = "max"`. Hook macro invocations have lines that exceed 79 cols and rustfmt does not reformat inside macros — leave them alone.
- `cargo clippy --release` — there is no CI lint step, but clippy is the expected sanity check before commits.
- `rust-toolchain.toml` pins channel `stable`. Edition is 2021, MSRV is 1.80.1.
- `cargo test` runs the inline unit tests for `is_path_under_secrets` (path-decision logic), the `is_secret_path` wrapper, `either_secret`, and the `hook!` macro's `dlsym`/`ENOSYS`-fallback machinery in `src/hook.rs`. Linux integration tests in `tests/preload.rs` spawn `LD_PRELOAD`'d children to exercise hook bodies end-to-end. macOS has a separate `tests/macos_interpose.rs` that *does not* run with `DYLD_INSERT_LIBRARIES` (real interpose re-enters our hooks from `realpath` during `K8S_SECRETS` `LazyLock` init and deadlocks); it only inspects the built dylib's `__DATA,__interpose` section via `otool`. Both test files honor `SECRETBRO_BUILD_TARGET` so cross-compiled cdylibs are located/built under `target/<triple>/debug/`.
- **musl `cdylib` config:** `x86_64-unknown-linux-musl` defaults to `crt-static`, which makes cargo silently drop the `cdylib` crate type. `.cargo/config.toml` disables `crt-static` for both musl targets, and `build.rs` resolves the toolchain's bundled `libunwind.a` and writes a one-line linker-script `libgcc_s.so` into `OUT_DIR` (added to the linker search path) — this aliases the `-lgcc_s` that Rust's musl target spec emits onto the bundled libunwind, since stock Debian `musl-tools` and Alpine don't ship a `libgcc_s.so.1`. Net result: plain `cargo build --release --target {x86_64,aarch64}-unknown-linux-musl` produces a `libsecretbro.so` whose only `NEEDED` is `libc.so` (musl), with no runtime dep on `libgcc_s`. `build.rs` is a no-op for non-musl targets.

To exercise the library locally:
```
LD_PRELOAD=./target/release/libsecretbro.so <command>     # Linux
DYLD_INSERT_LIBRARIES=./target/release/libsecretbro.dylib <command>  # macOS
```

## Architecture

Code is split between `src/lib.rs` (hook bodies + path-decision logic) and `src/hook.rs` (the `hook!` and `real!` macros, plus `dlsym_next` and the `ENOSYS` fallback). The shape is:

1. **Hooked libc functions** — declared via `hook! { unsafe fn name(...) -> ret => my_name { ... } }` (the macro is defined in `src/hook.rs` and brought into scope by `#[macro_use] mod hook;` at the top of `src/lib.rs`). Hooks fall into two intent buckets crossed with four cfg-gating tiers:

   *Intent:*
   - **Read** (returns sentinel on hit): `creat`, `open*`, `fopen*`, `access`, `readlink*`, `opendir`, `stat*`, `lstat*`, `fstatat*`, `faccessat`, `name_to_handle_at`, `statx`, `__xstat*`/`__lxstat*`/`__fxstatat*`.
   - **Modify** (mutating syscalls; deny if either side resolves into secrets via `either_secret` for two-path ops): `mkdir(at)`, `rmdir`, `unlink(at)`, `truncate(64)`, `chmod`, `fchmodat`, `chown`, `lchown`, `fchownat`, `utime`, `utimes`, `utimensat`, `mknod(at)`, `rename(at)`, `renameat2`, `link(at)`, `symlink(at)`.

   *Gating tiers:*
   - **Cross-platform** (Linux + macOS): the basic POSIX read/modify set (`open`, `creat`, `fopen`, `freopen`, `access`, `readlink`, `opendir`, `mkdir`, `rmdir`, `unlink`, `truncate`, `chmod`, `chown`, `lchown`, `utime`, `utimes`, `mknod`, `rename`, `link`, `symlink`).
   - **`#[cfg(target_os = "linux")]`**: `stat`, `lstat`, `fstatat`, `faccessat`, `readlinkat`, `name_to_handle_at`, plus the `*at` modify family (`mkdirat`, `unlinkat`, `fchmodat`, `fchownat`, `mknodat`, `utimensat`, `renameat`, `linkat`, `symlinkat`). Linux-only because on x86_64 macOS the real `stat`-family symbols are mangled (`stat$INODE64` etc.) and a plain hook would not intercept them.
   - **`#[cfg(all(target_os = "linux", target_env = "gnu"))]`**: glibc-only — `statx`, `renameat2`, the LFS `*64` variants (`creat64`, `open64`, `openat64`, `fopen64`, `freopen64`, `stat64`, `lstat64`, `fstatat64`, `truncate64`), and the `__xstat`/`__lxstat`/`__fxstatat`/`__xstat64`/`__lxstat64`/`__fxstatat64` versioning shims (glibc < 2.33 routed `stat`-family through these; ≥ 2.33 still exports the stubs, so hooking both generations covers either, and the `dlsym`/`ENOSYS` fallback in `hook.rs` makes a missing symbol a runtime no-op rather than a link error). The `*64` symbols are a glibc convention that does not exist on musl or macOS.

   Each hook returns the libc error sentinel (`-1` for `c_int`/`ssize_t`, `null_mut()` for `*mut FILE`/`*mut DIR`) when `is_secret_path` (or `either_secret` for two-path ops) rejects the path; otherwise it forwards to `real!(name)(args)`.

2. **Path-decision helpers** (single chokepoint, three layers):
   - **`is_path_under_secrets(bytes, secrets) -> bool`** — pure logic, unit-testable without globals. Reads the path as raw bytes (via `OsStr::from_bytes`) so non-UTF8 components are not corrupted. Always `canonicalize()`s so symlink redirects into the secrets directory are still caught; on failure (typically a missing leaf, e.g. `creat()` of a new file), it canonicalizes the parent and re-attaches the leaf so creates into secrets are still detected.
   - **`is_secret_path(pathname)`** / **`is_secret_path_with(pathname, secrets)`** — `unsafe` wrappers over the C string boundary. On hit, set `errno = EACCES` via `get_errno()` so callers just return the sentinel. On miss, snapshot `errno` *before* the canonicalize attempt and restore it after, because `realpath` perturbs `errno` and the caller is about to forward to real libc — the host program must see libc's natural error, not our probe's noise.
   - **`either_secret(p1, p2)`** / **`either_secret_with(...)`** — two-path operations (`rename`, `link`, `symlink`, and their `*at`/`*2` variants) deny if *either* side resolves into secrets, so a secret can't be moved out, hard-linked elsewhere, or shadowed by a symlink whose target is in secrets.

3. **`K8S_SECRETS: LazyLock<Option<PathBuf>>`** — canonicalized secrets directory, resolved once on first hook invocation. `None` means "directory missing or unresolvable, library is a no-op." Stored as `Option` rather than `unwrap`ed because the release profile uses `panic = "abort"`, which would otherwise abort the host process when the directory is absent. Source overridable via `SECRETBRO_PATH`.

4. **Platform-specific errno** — `get_errno()` returns `libc::__errno_location()` on Linux and `libc::__error()` on macOS. A `compile_error!` rejects other targets; new platform support requires extending this function.

5. **`hook!` macro internals** — the Linux expansion stamps each hook with a `#[no_mangle] pub unsafe extern "C" fn` plus a per-symbol `OnceLock<fn ptr>` resolved lazily via `dlsym(RTLD_NEXT, "name\0")`. If `dlsym` returns null (symbol absent in the loaded libc — e.g. `renameat2` on glibc < 2.28, or the `__xstat` family on glibc ≥ 2.33 depending on configuration), the hook installs `__enosys_fallback` which sets `errno = ENOSYS` and returns the type's `HookSentinel` (`-1` for ints/ssize, `null_mut()` for pointers), with a one-line warning emitted to stderr exactly once on first miss. The macOS expansion is structurally different: a `#[link_section = "__DATA,__interpose"]` static pairs hook and target pointers, processed by dyld at load time — no `dlsym`, no fallback.

6. **`file_handle` struct** — manual `#[repr(C)]` FFI shim (`u32 handle_bytes`, `i32 handle_type`, `[u8; 0] f_handle` to mirror the kernel struct's flexible-array tail) because `libc` does not expose it. Only used to type the `name_to_handle_at` hook signature; fields are never read or written.

7. **Variadic ABI shortcut** — `open`/`openat` and the `*64` variants are variadic in C (`mode` is consumed only when `O_CREAT` is in `flags`), but the `hook!` macro can't model varargs. Each is declared with a fixed `mode: mode_t` parameter; on AMD64 SysV / AArch64 AAPCS, the libc implementations ignore the unused register when `O_CREAT` is absent. Strict ABI mismatch, benign on these targets — do not extend this assumption to other architectures without testing.

### Adding a new libc hook

Match the existing template exactly. Single-path hook:

```rust
hook! {
    unsafe fn func(arg: T, pathname: *const c_char, ...) -> RetType => my_func {
        unsafe {
            if is_secret_path(pathname) {
                <libc-error-sentinel>          // -1, null_mut(), etc.
            } else {
                real!(func)(arg, pathname, ...)
            }
        }
    }
}
```

Two-path hook (rename/link/symlink shape) — call `either_secret`:

```rust
hook! {
    unsafe fn func(oldpath: *const c_char, newpath: *const c_char) -> c_int => my_func {
        unsafe {
            if either_secret(oldpath, newpath) {
                -1
            } else {
                real!(func)(oldpath, newpath)
            }
        }
    }
}
```

For glibc-only LFS `*64` variants, glibc-only modern syscalls (`renameat2`, `statx`), and the `__xstat` family, gate on `#[cfg(all(target_os = "linux", target_env = "gnu"))]` (not `target_arch = "x86_64"` — that gate was wrong on both axes, missing aarch64-gnu and emitting dead symbols on x86_64-musl). For Linux-only POSIX `*at` variants and `name_to_handle_at`, gate on `#[cfg(target_os = "linux")]`. If the symbol may not exist in the loaded libc (e.g. cross-glibc-version compatibility), no extra work is needed — the macro's `dlsym`/`ENOSYS` fallback handles it. The existing hooks are the reference.

## Behavioral pitfalls (non-obvious)

- **`is_secret_path` collapses three outcomes into two — and "indeterminate" maps to *allow*.** Null pointer, empty path, `K8S_SECRETS = None`, or `canonicalize()` failures even for the parent are all treated as "not a secret" so the real libc call proceeds and produces its natural error (e.g. `ENOENT`). This is deliberate: this library *adds* deny rules for a subset of paths and must not break unrelated I/O. Earlier versions denied on canonicalize-error and broke every `creat()`/`open(O_CREAT)` of a new file anywhere on the filesystem; do not reintroduce that.
- **`is_secret_path_with` snapshots and restores `errno` on miss.** `realpath` clobbers `errno` on failure, but the host program is about to call real libc and must see *its* errno, not our probe's. Tests pin this contract (`is_secret_path_preserves_errno_on_miss`) — preserve it when refactoring the wrapper.
- **Every hooked call canonicalizes.** There is no lexical fast-path; `is_secret_path` always invokes `realpath` (or `parent.canonicalize()` when the leaf is missing) so symlinks redirecting into secrets are still detected. The cost is one `realpath` per hooked syscall — acceptable on tmpfs/dcache, and required to keep the deny rule honest for benign callers.
- **TOCTOU between `is_secret_path` and the real syscall** is unavoidable for path-based interposition; an adversary that can race symlink edits can bypass the control. Out of scope.
- **No allocator/runtime initialization.** Code runs inside arbitrary host processes from the moment they dlopen the library. Do not introduce dependencies that require global initialization, threads, or async runtimes.
- **`src/hook.rs` resolves real libc symbols via `dlsym(RTLD_NEXT, ...)` on Linux** (cached per-symbol in a function-local `OnceLock<fn ptr>`). On macOS the mechanism is different — Mach-O `__DATA,__interpose` entries that dyld processes at load time. The two `hook!` macros encapsulate that platform split so `src/lib.rs` does not have to.
- **macOS integration tests cannot use real `DYLD_INSERT_LIBRARIES`.** Loading the dylib into a child causes `realpath` (called from `is_secret_path` on first hook) to re-enter our hooks during `K8S_SECRETS` `LazyLock` initialization, deadlocking the child. `tests/macos_interpose.rs` works around this by inspecting the built dylib's `__DATA,__interpose` section with `otool` instead. Linux has no such issue (`dlsym(RTLD_NEXT)` resolves real libc directly).

## Distribution

Releases are driven by `cargo-dist` (version pinned in `dist-workspace.toml`, currently `0.28.6`). The GitHub Actions workflow at `.github/workflows/release.yml` is auto-generated by `dist init` and should not be hand-edited; regenerate it with `dist init` after changing `dist-workspace.toml`. Release targets: `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`. The workflow triggers on tags matching `**[0-9]+.[0-9]+.[0-9]+*`.

## `LD_PRELOAD` constraints to surface to users

The README documents these and code changes cannot work around them — preserve the wording when editing:
- `LD_PRELOAD` is ignored in secure-execution mode (setuid/setgid binaries, binaries with file capabilities like `CAP_NET_BIND_SERVICE`).
- On Alpine Linux (musl), `LD_PRELOAD` is *completely* dropped for such binaries, not merely filtered.
