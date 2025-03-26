# secretbro

[![GitHub license](https://img.shields.io/github/license/dkorunic/secretbro.svg)](https://github.com/dkorunic/secretbro/blob/master/LICENSE.txt)
[![GitHub release](https://img.shields.io/github/release/dkorunic/secretbro.svg)](https://github.com/dkorunic/secretbro/releases/latest)
[![Rust Report Card](https://rust-reportcard.xuri.me/badge/github.com/dkorunic/secretbro)](https://rust-reportcard.xuri.me/report/github.com/dkorunic/secretbro)
[![release](https://github.com/dkorunic/secretbro/actions/workflows/release.yml/badge.svg)](https://github.com/dkorunic/secretbro/actions/workflows/release.yml)

## About

Secretbro is a LD_PRELOAD based filesystem access control for Kubernetes secrets directory (`/var/run/secrets/kubernetes.io`). It prevents unsolicited filesystem I/O access that could lead to content leaking from 3rd party software that does not need to access Kubernetes secrets in the first place.

It works by hooking various filesystem path-related `libc` functions and restricting their access (erroring out in case it is attempted to read K8s secrets) without requiring any source or binary modifications for the 3rd party K8s software you want to secure.

## Usage

Upon compilation and installation to any standard library directory, library (resulting `libsecretbro.so` file) can be freely preloaded (in shell scripts, S6 overlay, etc.), for instance on Linux via LD_PRELOAD environment variable:

```shell
LD_PRELOAD=/usr/lib/libsecretbro.so nginx ...
```

On macOS, typically DYLD_INSERT_LIBRARIES environment variable is used for the same purpose.

Typical example of `libsecretbro.so` in action:

```shell
# echo "Terrible secret" > /var/run/secrets/kubernetes.io/foobaz

# ls -al /var/run/secrets/kubernetes.io/foobaz
-rw-r--r-- 1 root root 16 Mar 26 19:24 /var/run/secrets/kubernetes.io/foobaz

# LD_PRELOAD=/usr/lib/libsecretbro.so cat /var/run/secrets/kubernetes.io/foobaz
cat: /var/run/secrets/kubernetes.io/foobaz: Permission denied
```