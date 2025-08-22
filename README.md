# secretbro

[![GitHub license](https://img.shields.io/github/license/dkorunic/secretbro.svg)](https://github.com/dkorunic/secretbro/blob/master/LICENSE.txt)
[![GitHub release](https://img.shields.io/github/release/dkorunic/secretbro.svg)](https://github.com/dkorunic/secretbro/releases/latest)
[![release](https://github.com/dkorunic/secretbro/actions/workflows/release.yml/badge.svg)](https://github.com/dkorunic/secretbro/actions/workflows/release.yml)

![](spycrab.png)

## About

Secretbro is an interposition library (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) for the filesystem access control on Kubernetes secrets directory (`/var/run/secrets/kubernetes.io`). It prevents unsolicited filesystem I/O access that could lead to [content leaking](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities) from 3rd party software that does not need to have any access to Kubernetes secrets in the first place.

It works by hooking various filesystem path-related `libc` functions and restricting their access (erroring out in case it is attempted to read K8s secrets) without requiring any source or binary modifications for the 3rd party K8s software you want to secure.

## Usage

Upon compilation and installation to any standard library directory, library (resulting `libsecretbro.so` file) can be freely preloaded (in shell scripts, S6 overlay, etc.), for instance on Linux via `LD_PRELOAD` environment variable:

```shell
LD_PRELOAD=/usr/lib/libsecretbro.so nginx ...
```

On macOS, typically `DYLD_INSERT_LIBRARIES` environment variable is used for the same purpose.

Typical example of `libsecretbro.so` in action:

```shell
# echo "Terrible secret" > /var/run/secrets/kubernetes.io/foobaz

# ls -al /var/run/secrets/kubernetes.io/foobaz
-rw-r--r-- 1 root root 16 Mar 26 19:24 /var/run/secrets/kubernetes.io/foobaz

# LD_PRELOAD=/usr/lib/libsecretbro.so cat /var/run/secrets/kubernetes.io/foobaz
cat: /var/run/secrets/kubernetes.io/foobaz: Permission denied
```

Note that due to security reasons, dynamic linker `ld.so` in secure-execution mode (for setuid/setgid binaries, for binaries with capabilities set with `setcap`, etc.) has some specific requirements and limitations how `LD_PRELOAD` is processed:

> In secure-execution mode, preload pathnames containing slashes are ignored. Furthermore, shared objects are preloaded only from the standard search directories and only if they have set-user-ID mode bit enabled (which is not typical).
>
> ...
>
> This variable is ignored in secure-execution mode.
> Within the pathnames specified in LD_LIBRARY_PATH, the dynamic linker expands the tokens $ORIGIN, $LIB, and $PLATFORM (or the versions using curly braces around the names) as described above in Dynamic string tokens. Thus, for example, the following would cause a library to be searched for in either the lib or lib64 subdirectory below the directory containing the program to be executed:

Note that this doesn't only apply to `CAP_SYS_ADMIN` and/or `CAP_NET_ADMIN`, but also to `CAP_NET_BIND_SERVICE` etc.
