<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/assets/kemlock-wordmark-dark.svg">
    <img alt="Kemlock" src=".github/assets/kemlock-wordmark-light.svg" width="360">
  </picture>
</p>

<h3 align="center">Kemlock-core</h3>

<p align="center">
  The pure-Dart core that the Kemlock app and the Kemlock browser extension share.
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licence: GPL-3.0-or-later" src="https://img.shields.io/badge/licence-GPL--3.0--or--later-blue"></a>
  <a href="https://github.com/Arsslensoft/Kemlock-core/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/Arsslensoft/Kemlock-core?display_name=tag&include_prereleases"></a>
  <img alt="Status: in development" src="https://img.shields.io/badge/status-in%20development-orange">
  <br>
  <a href="https://github.com/Arsslensoft/Kemlock-core/actions/workflows/checks.yml"><img alt="Checks" src="https://github.com/Arsslensoft/Kemlock-core/actions/workflows/checks.yml/badge.svg"></a>
  <a href="https://github.com/Arsslensoft/Kemlock-core/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/Arsslensoft/Kemlock-core/actions/workflows/codeql.yml/badge.svg"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Arsslensoft/Kemlock-core"><img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/Arsslensoft/Kemlock-core/badge"></a>
  <br>
  <img alt="Dart 3.13" src="https://img.shields.io/badge/Dart-3.13-0175C2?logo=dart&logoColor=white">
  <img alt="dart2wasm" src="https://img.shields.io/badge/dart2wasm-supported-654FF0?logo=webassembly&logoColor=white">
  <img alt="ML-KEM-1024" src="https://img.shields.io/badge/ML--KEM--1024-post--quantum-success">
</p>

<p align="center">
  <a href="#what-it-will-hold">What it will hold</a> ·
  <a href="#using-it">Using it</a> ·
  <a href="#checks">Checks</a> ·
  <a href="#releases">Releases</a> ·
  <a href="#the-byte-format-rule">Byte formats</a> ·
  <a href="https://github.com/Arsslensoft/Kemlock-browser">Browser extension</a> ·
  <a href="https://github.com/Arsslensoft/Kemlock">Kemlock app</a> ·
  <a href="https://github.com/Arsslensoft/Kemlock-Server">Kemlock Server</a>
</p>

---

Kemlock is a post-quantum encrypted authenticator and password manager. Kemlock-core is the part of
it that has no screen: the code that keeps a vault safe and in sync, written once in Dart with no
Flutter in it.

> **In development.** The code is moving in from the Kemlock app. Until it has, this package is
> an empty placeholder: one library with nothing in it, and its test.

## What it will hold

Once the code has moved in from the app:

- 🔐 **Crypto**: ML-KEM-1024 and ML-DSA, scrypt, AES-GCM, OPAQUE and the account crypto.
- 🗄️ **The vault**: its models and its store.
- 🔄 **Sync engines** for WebDAV, Vaultwarden and Kemlock Server.
- 🔢 **One-time codes** (OTP) and the **password generator**.
- 🌐 **Site matching**: which login or code belongs to which website.

## Who uses it

Once the code has moved in, two programs depend on it:

- The [Kemlock app](https://github.com/Arsslensoft/Kemlock) for iOS and Android, a Flutter app that
  runs the package on the Dart VM. Its repository is private for now.
- The [Kemlock browser extension](https://github.com/Arsslensoft/Kemlock-browser) for Chrome, Edge
  and Firefox, which compiles the package to WebAssembly with dart2wasm.

So the code is pure Dart, with no Flutter and no `dart:ui`, and what reaches the extension has no
unguarded `dart:io`. The tests run both on the VM and, compiled with dart2wasm, in Chrome.

## Using it

The package is not on pub.dev. Depend on it as a git dependency pinned to a commit, so that a build
is the same on any day. In `pubspec.yaml`:

```yaml
dependencies:
  kemlock_core:
    git:
      url: https://github.com/Arsslensoft/Kemlock-core.git
      ref: <the full 40-character commit SHA>
```

Each [release](https://github.com/Arsslensoft/Kemlock-core/releases) names the commit to pin in its
notes. Use the full SHA, not a branch or a tag: a tag can be moved, a commit cannot. Then
`import 'package:kemlock_core/kemlock_core.dart';`.

## Checks

```bash
dart pub get
dart format --output=none --set-exit-if-changed .   # the page width is 140
dart analyze --fatal-infos
dart test                                           # on the Dart VM
dart test -p chrome -c dart2wasm                    # compiled to WebAssembly, run in Chrome
node .github/scripts/check-licences.mjs            # after dart pub get
```

On GitHub, [`checks.yml`](.github/workflows/checks.yml) runs them as the jobs Lint, Test and Test
(wasm), with Dependencies, DCO, Licences and Security beside them; the pull request's title is
checked by `title.yml`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Every push to `main` is released by [`release.yml`](.github/workflows/release.yml) once the checks
pass. The next version comes from the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification) since the last
`v*` tag: a `feat` is a minor release, a `fix`, `perf` or `revert` (or git's `Revert "..."`) a
patch, and a `!` or a `BREAKING CHANGE` a major one (a minor one while the major is 0). A push of
`docs`, `chore`, `test`, `ci`, `style`, `refactor` or `build` commits alone releases nothing. The
first release is the version `pubspec.yaml` holds, and a later one is the last tag bumped by the
commits, or `pubspec.yaml`'s version when you have set it higher by hand (a release that needs a
jump, to 1.0.0). Nothing is committed for a release: the version is its tag's (`v0.2.0`).

A release is an annotated tag and a GitHub release whose notes group the changes by type. It has no
files to download, since the app and the extension pin a commit: its notes end with the full commit
SHA to pin.

## The byte-format rule

The formats that other versions of Kemlock read (the vault, exports, sync files, `kem1`, manifests,
OPAQUE messages, the account crypto) stay byte for byte what they were, or vaults and backups
already on people's devices stop opening. The test vectors and fixtures, which will be in
`test/fixtures/` once the code moves in, are what older versions wrote: they are never regenerated
or edited, and a change to a format comes
with a version label and a fixture that proves the old data still opens. CodeRabbit and the review
hold every pull request to this.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) for a security problem; the
crypto lives here, so a report about it matters most. Every commit is signed off
([DCO](CONTRIBUTING.md#signing-off-dco)), and the [Code of Conduct](CODE_OF_CONDUCT.md) applies.

## Licence

Kemlock-core is free software under the [GNU General Public License v3.0 or later](LICENSE).
