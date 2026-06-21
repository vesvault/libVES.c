# Contributing to libVES.c

Thanks for your interest. libVES.c is the C implementation of the VESvault API
library and the `ves` CLI — it's security-critical software, backed by a hosted
service, that real users trust with their data. The guidelines below keep
contributions safe to merge.

## Reporting security vulnerabilities

**Do not open a public issue, pull request, or discussion for security problems.**
Follow [SECURITY.md](SECURITY.md) — email **security@vesvault.com**. This is the
single most important rule here.

## Bugs and small fixes

Bug reports and small, focused fixes are welcome via issues and pull requests:

- Search existing issues first.
- For a bug, include your version (`ves -V` or the commit), platform, build
  options (e.g. `--with-oqs`), and a minimal reproduction. **Redact any real
  VESkeys, tokens, or private keys.**
- Keep PRs focused; one logical change per PR is easiest to review.

## Larger changes — start with an issue

Because this library and CLI interoperate with a hosted protocol, changes to
**cryptography, the public API surface, or the wire protocol should start as an
issue** before you write code. We can't always merge changes that affect the
protocol or the service, and a short discussion up front saves wasted effort.

## Building and testing

```sh
./configure                   # add --without-oqs to build without liboqs (not recommended)
make
```

Dependencies are OpenSSL (`libcrypto`), cURL (`libcurl`), and liboqs (post-quantum
KEMs, **required by default** — see the [Post-quantum](README.md#post-quantum) notes).
On Windows, build from an MSYS2 MinGW 64-bit shell — see [README.md](README.md)
and [INSTALL](INSTALL).

The CI workflow builds the library and CLI on Linux, macOS, and Windows. It does
**not** run `tests/`: that suite drives the live VES API and needs two real,
synced VES accounts (see `tests/vestest.conf`). To run it locally, copy your
account settings into `~/.vestest.conf` and execute the scripts in `tests/`.

## Style

Match the style of the surrounding code — indentation, naming, and bracing.
Builds should be warning-clean. Please don't reformat unrelated code in a PR.

## Licensing

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE).
