# Security policy

## Reporting a vulnerability

Report a security problem privately, not in a public issue: use
[Report a vulnerability](https://github.com/Arsslensoft/Kemlock-core/security/advisories/new) on
this repository's Security tab. The report stays between you and the maintainers until a fixed
commit is out, and the advisory is published with it. Please keep the details to yourself until
then.

Say as much as you can of:

- the commit or version of Kemlock-core, and the Dart version,
- what an attacker gains, and from where: the server the vault syncs with, the network, a file that
  is imported or synced, or someone with a copy of the vault,
- the steps, or the smallest code, that show it.

## Scope

This repository holds the crypto and the vault code that the Kemlock app and the browser
extension share, so reports about it matter most. A report belongs here when the problem is in
something it makes or does; a problem in the app's screens or its platform code belongs to the app,
and a report here is passed on:

- the cryptography: how the keys are made, derived, wrapped and used (ML-KEM-1024, ML-DSA, scrypt,
  AES-GCM, the account crypto), the OPAQUE login, nonces and randomness, comparisons that are not in
  constant time, and a key, a password or a code that is logged or left in memory longer than it
  should be,
- the vault: its models, its store, and the formats it writes and reads (the vault, exports, sync
  files, `kem1`, manifests), including a file that crashes the reader or makes it do more than it
  should,
- the sync engines (WebDAV, Vaultwarden, Kemlock Server): what they send, to whom, and how they
  check what they get back,
- OTP, the password generator and site matching, when a flaw weakens a code or a password or makes
  a site match another,
- how the package is built and released (`.github/workflows/`): a workflow that leaks a secret.

A problem in the Kemlock app, in the browser extension or in Kemlock Server belongs to that
project; their repositories are linked from the [README](README.md), and the app's and the
server's are private for now, so report it here and it will be passed on. When it is not clear
which it is, report it here.

## Supported versions

Fixes go into a new commit on `main`, and a release when the change warrants one; an older release
is not patched. The app and the extension take a fix by moving the commit they pin.
