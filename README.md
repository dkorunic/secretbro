# secretbro

[![GitHub license](https://img.shields.io/github/license/dkorunic/secretbro.svg)](https://github.com/dkorunic/secretbro/blob/master/LICENSE.txt)
[![GitHub release](https://img.shields.io/github/release/dkorunic/secretbro.svg)](https://github.com/dkorunic/secretbro/releases/latest)
[![release](https://github.com/dkorunic/secretbro/actions/workflows/release.yml/badge.svg)](https://github.com/dkorunic/secretbro/actions/workflows/release.yml)

![](spycrab.png)

## About

Secretbro is an interposition library (`LD_PRELOAD` on Linux, `DYLD_INSERT_LIBRARIES` on macOS) that enforces filesystem access control over the Kubernetes secrets directory (`/var/run/secrets/kubernetes.io`). It blocks unsolicited reads and writes that could otherwise [leak secrets](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) through third-party software that has no legitimate need for them.

It works by hooking the path-based `libc` functions that actually read or mutate secret contents, and rejecting any call whose path resolves inside the secrets directory (returning `EACCES`). No source or binary modification of the protected program is required. The hooks cover the content-open family (`open`, `openat`, `creat`, `fopen`, `freopen`) and the modify family (`mkdir`, `rmdir`, `unlink`, `truncate`, `chmod`, `chown`, `rename`, `link`, `symlink`, …), plus their `*at` and glibc LFS (`*64`) variants on Linux.

Metadata-only calls (`stat`, `lstat`, `access`, `readlink`, `opendir`, `statx`, …) are deliberately **not** intercepted. Every hooked call canonicalizes its path through `realpath`, which is blocking and not async-signal-safe; processes that `stat`/`access` on a latency-sensitive hot path (e.g. HAProxy's event loop) would stall and trip watchdogs ([haproxytech/kubernetes-ingress#818](https://github.com/haproxytech/kubernetes-ingress/issues/818)). Blocking metadata reads buys little — a caller still cannot read a secret's bytes or move/shadow it — so the hook surface is limited to the calls that protect contents.

## Usage

Once `libsecretbro.so` is built and installed into a standard library directory, it can be preloaded from shell scripts, an S6 overlay, or anywhere else through the `LD_PRELOAD` environment variable on Linux:

```shell
LD_PRELOAD=/usr/lib/libsecretbro.so nginx ...
```

On macOS, use `DYLD_INSERT_LIBRARIES` instead.

A typical example of the library in action:

```shell
# echo "Terrible secret" > /var/run/secrets/kubernetes.io/foobaz

# ls -al /var/run/secrets/kubernetes.io/foobaz
-rw-r--r-- 1 root root 16 Mar 26 19:24 /var/run/secrets/kubernetes.io/foobaz

# LD_PRELOAD=/usr/lib/libsecretbro.so cat /var/run/secrets/kubernetes.io/foobaz
cat: /var/run/secrets/kubernetes.io/foobaz: Permission denied
```

For security reasons, the dynamic linker `ld.so` restricts how `LD_PRELOAD` is processed in secure-execution mode — that is, for setuid/setgid binaries, binaries with file capabilities set via `setcap`, and similar:

> In secure-execution mode, preload pathnames containing slashes are ignored. Furthermore, shared objects are preloaded only from the standard search directories and only if they have set-user-ID mode bit enabled (which is not typical).
>
> ...
>
> This variable is ignored in secure-execution mode.
> Within the pathnames specified in LD_LIBRARY_PATH, the dynamic linker expands the tokens $ORIGIN, $LIB, and $PLATFORM (or the versions using curly braces around the names) as described above in Dynamic string tokens. Thus, for example, the following would cause a library to be searched for in either the lib or lib64 subdirectory below the directory containing the program to be executed:

This applies to any elevated capability, not just `CAP_SYS_ADMIN` or `CAP_NET_ADMIN` — `CAP_NET_BIND_SERVICE` alone is enough to trigger it.

On Alpine Linux (musl) containers, `LD_PRELOAD` is dropped entirely for setuid/setgid/setcap binaries rather than merely filtered:

> ... This variable is completely ignored in programs invoked setuid, setgid, or with other elevated capabilities.

## Configuration

The protected directory defaults to `/var/run/secrets/kubernetes.io` and can be overridden at process start through the `SECRETBRO_PATH` environment variable:

```shell
SECRETBRO_PATH=/etc/secrets LD_PRELOAD=/usr/lib/libsecretbro.so myapp ...
```

`SECRETBRO_PATH` is read once on the first hooked call and cached for the lifetime of the process; later changes to the environment have no effect.

If the configured directory does not exist or cannot be canonicalized at that point, the library falls back to a no-op and every call passes straight through to `libc`. This makes it safe to preload unconditionally on hosts that may or may not be Kubernetes pods.
