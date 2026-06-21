```
          ___       ___
         /   \     /   \    VESvault
         \__ /     \ __/    Encrypt Everything without fear of losing the Key
            \\     //                   https://vesvault.com  https://ves.host
             \\   //
     ___      \\_//
    /   \     /   \         libVES:                      VESvault API library
    \__ /     \ __/
       \\     //            VES Utility:   A command line interface to libVES
        \\   //
         \\_//              - Key Management and Exchange
         /   \              - Item Encryption and Sharing
         \___/              - Stream Encryption
```

# libVES.c

[![CI](https://github.com/vesvault/libVES.c/actions/workflows/ci.yml/badge.svg)](https://github.com/vesvault/libVES.c/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/vesvault/libVES.c)](https://github.com/vesvault/libVES.c/releases)
[![License](https://img.shields.io/github/license/vesvault/libVES.c)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-blue)

**End-to-end encryption you can actually recover from.**

`libVES.c` is the C implementation of the VESvault API library, plus **`ves`**, a
command-line interface to it. It does end-to-end encryption with three things most
E2E stacks leave you to build (or skip) yourself:

- **Key management & exchange** — keys are generated, encrypted, and shared between
  users through a verifiable chain of trust.
- **Item encryption & sharing** — store a value encrypted, share it with another user
  by reference, revoke it later.
- **Stream encryption** — encrypt files and streams of any size under a key kept in
  your vault.

## Why VES exists

True end-to-end encryption has a brutal failure mode: **lose the key and the data is
gone forever.** That single problem is why most products quietly fall back to
server-side encryption, where the provider can read everything.

VES is a key-management layer that makes encryption keys themselves recoverable —
through other devices and people you trust — **without the VESvault service ever seeing
your keys or your plaintext.** You get real end-to-end encryption *and* a way back in
when a device is lost.

> **Is that a backdoor?** No. Recovery works by re-sharing an encrypted key along a
> trust chain *you* define (your other devices, designated recovery contacts); the
> server only ever stores ciphertext it cannot decrypt. The mechanism — and its honest
> trade-offs — are written up in [doc/VESrecovery.md](doc/VESrecovery.md) and at
> <https://ves.host>. We welcome scrutiny of it.

## Quick start — the `ves` CLI

Build it (see [Installing](#installing)), then open an App Vault in the shared `demo`
domain (use your own identity in place of `me@example.com`), store an encrypted value,
and read it back:

```sh
ves -a //demo/me@example.com/ -E -o note-1 -i "hello"   # encrypt + store
ves -a //demo/me@example.com/ -E -o note-1 -ip          # decrypt + print  ->  hello
```

> **Domains.** A VES *domain* (the `demo` above) namespaces vaults and items. It may
> mirror a DNS domain, but it must be registered in VES first. Two kinds work without
> registration: **`demo`** — a shared sandbox, used in the examples here — and **`x-…`**
> — experimental domains (any name beginning with `x-`) that are created automatically
> on first use, giving you a private namespace to build against. Any other (real DNS)
> domain returns an error until it is registered through VES Enterprise.

Share that item with another VES user — they decrypt it with *their* key, you never
hand over a password (their vault must already exist in VES):

```sh
ves -a //demo/me@example.com/ -E -o note-1 \
    -s //demo/friend@example.com/
```

Stream-encrypt a file under a key kept in your vault, then decrypt it (list ciphers
with `ves -cl`):

```sh
ves -a //demo/me@example.com/ -E -o backup -c AES256GCM1K \
    -e -Pf data.tar -Cf data.tar.ves
ves -a //demo/me@example.com/ -E -o backup \
    -d -Cf data.tar.ves -Pf data.tar
```

Full option reference: `man ves`, or <https://ves.host/docs/ves-util>.

## Use it from C

The high-level API encrypts, stores, shares, and decrypts in a couple of calls:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libVES.h>

int main(void) {
    libVES_init("MyApp/1.0");

    /* An App Vault:  ves://domain/externalId/ */
    libVES *ves = libVES_new("ves://demo/me@example.com/");
    const char *veskey = "correct horse battery staple";
    libVES_unlock(ves, strlen(veskey), veskey);

    /* Encrypt, store, and share in one call (the target vault must exist) */
    const char *shares[] = { "ves://demo/friend@example.com/" };
    libVES_putValue(ves, "note-1", 5, "hello", 1, shares);

    /* Read it back — decrypts transparently */
    char *val = libVES_getValue(ves, "note-1", NULL, NULL);
    if (val) {
        printf("%s\n", val);
        free(val);
    } else {
        fprintf(stderr, "VES error: %s\n", libVES_errorStr(libVES_getError(ves)));
    }

    libVES_free(ves);
    return 0;
}
```

Link against `-lVES -lcrypto -lcurl`. Library reference: <https://ves.host/docs/libVES-c>.

## Installing

Requirements:

- **OpenSSL** — `libcrypto` + `openssl/*.h` (<https://www.openssl.org/source/>)
- **cURL** — `libcurl` + `curl/*.h` (<https://curl.se/download.html>)
- **liboqs** — post-quantum KEMs, **required by default** (<https://github.com/open-quantum-safe/liboqs>).
  Packaged by Homebrew (`brew install liboqs`), MSYS2, Fedora and Arch; on Debian/Ubuntu,
  [build it from source](https://github.com/open-quantum-safe/liboqs#quickstart). Pass
  `--without-oqs` to build a classical-only library (not recommended — see [Post-quantum](#post-quantum)).

GNU build:

```sh
./configure              # add --without-oqs to build without liboqs (not recommended)
make
sudo make install      # installs libVES.so*, libVES.a, libVES.h, libVES/*.h, and ves
```

Windows is built with the same GNU toolchain under [MSYS2](https://www.msys2.org/).
From the **MSYS2 MinGW 64-bit** shell, install the dependencies and build:

```sh
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl \
    mingw-w64-x86_64-curl mingw-w64-x86_64-liboqs autoconf automake libtool make
./configure
make
make install          # installs libVES.dll, libVES.a, libVES.h, and ves.exe
```

> If libcurl on Windows reports an SSL peer-certificate error, copy `etc/curl-ca-bundle.crt`
> next to `ves.exe` (or fetch the latest from <https://curl.se/ca/cacert.pem>).

Docker: a `Dockerfile` is included. See [`INSTALL`](INSTALL) for complete instructions.

## Post-quantum

Post-quantum key exchange is **on by default**. libVES links liboqs and uses **ML-KEM**
(FIPS 203) — the default parameter set is ML-KEM-768. List the key algorithms available in
your build with `ves -Gl`. This matters today: "harvest now, decrypt later" means data
exchanged with classical-only keys can be captured now and broken once quantum hardware
arrives, so we'd rather you have to opt *out* than remember to opt in.

You can build a classical-only library with `./configure --without-oqs` (it still
interoperates — keys carry their own algorithm — but newly generated keys won't be
post-quantum). Existing classical keys keep working either way.

## Real-time events

React to vault activity as it happens — an item shared with you, a key granted or revoked,
a new session opened. The `ves -W` command streams these events from the CLI; in C the
`libVES_Event` API (see [`lib/libVES/Event.h`](lib/libVES/Event.h)) delivers the same
stream. Useful for syncing, notifications, and reacting to shares and revocations without
polling your own state.

## Pricing & terms

VES has a **free tier**; paid usage is **priced by volume**. The library and CLI are
free and open source under the Apache License 2.0. See current terms and pricing at
<https://ves.host/terms_conditions> and <https://vesvault.com>.

## Contributing

Bug reports and small, focused fixes are welcome via issues and pull requests. Because
this is security-critical software backed by a hosted service, larger changes — new
cryptography, API-surface or protocol changes — should **start with an issue** before you
write code; we can't always merge changes that affect the protocol or the service.

Security issues are different: **please don't open a public issue or PR** — follow
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Copyright © 2018–2026
VESvault Corp.

## Links

- Documentation — <https://ves.host>
- libVES.c reference — <https://ves.host/docs/libVES-c>
- `ves` CLI reference — <https://ves.host/docs/ves-util>
- JavaScript library — <https://www.npmjs.com/package/libves>
