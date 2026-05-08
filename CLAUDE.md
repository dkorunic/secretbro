# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`secretbro` is a `cdylib` interposition library loaded via `LD_PRELOAD` (Linux) or `DYLD_INSERT_LIBRARIES` (macOS). It denies filesystem access to the Kubernetes secrets directory (`/var/run/secrets/kubernetes.io`) for the host process, without modifying the host binary or its source. The protected resource defaults to `K8S_SECRETS_PATH` in `src/lib.rs` and can be overridden at process start via the `SECRETBRO_PATH` environment variable (read once on first hook call).

## Build / Run / Format

- `cargo build --release` — produces `target/release/libsecretbro.{so,dylib}`. The release profile is opinionated (LTO=fat, `panic = "abort"`, `codegen-units = 1`, `strip = "symbols"`); debug builds will work for development but won't match what ships.
- `cargo fmt` — `rustfmt.toml` enforces `max_width = 79` and `use_small_heuristics = "max"`. Hook macro invocations have lines that exceed 79 cols and rustfmt does not reformat inside macros — leave them alone.
- `cargo clippy --release` — there is no CI lint step, but clippy is the expected sanity check before commits.
- `rust-toolchain.toml` pins channel `stable`. Edition is 2021, MSRV is 1.80.1.
- `cargo test` runs the inline unit tests for `is_path_under_secrets` (path-decision logic), the `is_secret_path` wrapper, and `either_secret`, plus the integration tests in `tests/preload.rs` that spawn `LD_PRELOAD`'d children to exercise hook bodies end-to-end.
- **musl `cdylib` config:** `x86_64-unknown-linux-musl` defaults to `crt-static`, which makes cargo silently drop the `cdylib` crate type. `.cargo/config.toml` disables `crt-static` for both musl targets, and `build.rs` resolves the toolchain's bundled `libunwind.a` and writes a one-line linker-script `libgcc_s.so` into `OUT_DIR` (added to the linker search path) — this aliases the `-lgcc_s` that Rust's musl target spec emits onto the bundled libunwind, since stock Debian `musl-tools` and Alpine don't ship a `libgcc_s.so.1`. Net result: plain `cargo build --release --target {x86_64,aarch64}-unknown-linux-musl` produces a `libsecretbro.so` whose only `NEEDED` is `libc.so` (musl), with no runtime dep on `libgcc_s`. `build.rs` is a no-op for non-musl targets.

To exercise the library locally:
```
LD_PRELOAD=./target/release/libsecretbro.so <command>     # Linux
DYLD_INSERT_LIBRARIES=./target/release/libsecretbro.dylib <command>  # macOS
```

## Architecture

Code is split between `src/lib.rs` (hook bodies + path-decision logic) and `src/hook.rs` (the `hook!` and `real!` macros, plus `dlsym_next`). The shape is:

1. **Hooked libc functions** — declared via `hook! { unsafe fn name(...) -> ret => my_name { ... } }` (the macro is defined in `src/hook.rs` and brought into scope by `#[macro_use] mod hook;` at the top of `src/lib.rs`). Three gating tiers:
   - **Cross-platform** (Linux + macOS): `creat`, `open`, `openat`, `fopen`, `freopen`, `access`, `readlink`, `opendir`.
   - **`#[cfg(target_os = "linux")]`**: `stat`, `lstat`, `fstatat`, `faccessat`, `readlinkat`, `name_to_handle_at`. Linux-only because on x86_64 macOS the real symbols are mangled (`stat$INODE64` etc.) and a plain hook would not intercept them.
   - **`#[cfg(all(target_os = "linux", target_env = "gnu"))]`**: `statx` and the LFS `*64` variants (`creat64`, `open64`, `openat64`, `fopen64`, `freopen64`, `stat64`, `lstat64`, `fstatat64`). The `*64` symbols are a glibc convention that does not exist on musl or macOS.
   Each hook returns the libc error sentinel (`-1` for `c_int`/`ssize_t`, `null_mut()` for `*mut FILE`/`*mut DIR`) when `is_secret_path` rejects the path; otherwise it forwards to `real!(name)(args)`.
2. **`is_secret_path(pathname) -> bool`** — single chokepoint. Returns `true` to deny (with `errno = EACCES` set via `get_errno()`); `false` to allow. The function reads the path as raw bytes (via `OsStr::from_bytes(CStr::from_ptr(p).to_bytes())`) so non-UTF8 components are not corrupted. It always `canonicalize()`s the path so symlink redirects into the secrets directory are still caught; if canonicalization fails (typically because the leaf doesn't exist, e.g. `creat()` of a new file), it falls back to canonicalizing the parent and re-attaching the leaf so creates targeting the secrets directory are still detected.
3. **`K8S_SECRETS: LazyLock<Option<PathBuf>>`** — canonicalized secrets directory, resolved once on first hook invocation. `None` means "directory missing or unresolvable, library is a no-op." Stored as `Option` rather than `unwrap`ed because the release profile uses `panic = "abort"`, which would otherwise abort the host process when the directory is absent.
4. **Platform-specific errno** — `get_errno()` returns `libc::__errno_location()` on Linux and `libc::__error()` on macOS. Other platforms are not handled; new platform support requires extending this function.
5. **`file_handle` struct** — manual `#[repr(C)]` FFI shim (`u32 handle_bytes`, `i32 handle_type`, `[u8; 0] f_handle` to mirror the kernel struct's flexible-array tail) because `libc` does not expose it. Only used to type the `name_to_handle_at` hook signature; fields are never read or written.

### Adding a new libc hook

Match the existing template exactly:

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

For glibc-only LFS `*64` variants, gate on `#[cfg(all(target_os = "linux", target_env = "gnu"))]` (not `target_arch = "x86_64"` — that gate was wrong on both axes, missing aarch64-gnu and emitting dead symbols on x86_64-musl). For Linux-only modern syscalls (`*at`, `statx`, `name_to_handle_at`), gate on `#[cfg(target_os = "linux")]`. The existing hooks are the reference.

## Behavioral pitfalls (non-obvious)

- **`is_secret_path` collapses three outcomes into two — and "indeterminate" maps to *allow*.** Null pointer, empty path, `K8S_SECRETS = None`, or `canonicalize()` failures even for the parent are all treated as "not a secret" so the real libc call proceeds and produces its natural error (e.g. `ENOENT`). This is deliberate: this library *adds* deny rules for a subset of paths and must not break unrelated I/O. Earlier versions denied on canonicalize-error and broke every `creat()`/`open(O_CREAT)` of a new file anywhere on the filesystem; do not reintroduce that.
- **Every hooked call canonicalizes.** There is no lexical fast-path; `is_secret_path` always invokes `realpath` (or `parent.canonicalize()` when the leaf is missing) so symlinks redirecting into secrets are still detected. The cost is one `realpath` per hooked syscall — acceptable on tmpfs/dcache, and required to keep the deny rule honest for benign callers.
- **TOCTOU between `is_secret_path` and the real syscall** is unavoidable for path-based interposition; an adversary that can race symlink edits can bypass the control. Out of scope.
- **No allocator/runtime initialization.** Code runs inside arbitrary host processes from the moment they dlopen the library. Do not introduce dependencies that require global initialization, threads, or async runtimes.
- **`src/hook.rs` resolves real libc symbols via `dlsym(RTLD_NEXT, ...)` on Linux** (cached per-symbol in a function-local `OnceLock<fn ptr>`). On macOS the mechanism is different — Mach-O `__DATA,__interpose` entries that dyld processes at load time. The two `hook!` macros encapsulate that platform split so `src/lib.rs` does not have to.

## Distribution

Releases are driven by `cargo-dist` (version pinned in `dist-workspace.toml`, currently `0.28.6`). The GitHub Actions workflow at `.github/workflows/release.yml` is auto-generated by `dist init` and should not be hand-edited; regenerate it with `dist init` after changing `dist-workspace.toml`. Release targets: `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`. The workflow triggers on tags matching `**[0-9]+.[0-9]+.[0-9]+*`.

## `LD_PRELOAD` constraints to surface to users

The README documents these and code changes cannot work around them — preserve the wording when editing:
- `LD_PRELOAD` is ignored in secure-execution mode (setuid/setgid binaries, binaries with file capabilities like `CAP_NET_BIND_SERVICE`).
- On Alpine Linux (musl), `LD_PRELOAD` is *completely* dropped for such binaries, not merely filtered.
