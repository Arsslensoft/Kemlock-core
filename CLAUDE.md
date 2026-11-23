# Kemlock-core

The pure-Dart core of Kemlock, a post-quantum encrypted authenticator and password manager. Once
the code has moved in from the app it will hold the crypto (ML-KEM-1024, ML-DSA, scrypt, AES-GCM,
OPAQUE, account crypto), the vault models and store, the sync engines (WebDAV, Vaultwarden, Kemlock
Server), OTP, the password generator and site matching. **Today it is an empty placeholder**: one
library and its test. Public, GPL-3.0-or-later, `git@github.com:Arsslensoft/Kemlock-core.git`.

Two consumers depend on it as a git dependency pinned to a commit (it is not on pub.dev): the
Flutter app (`git@github.com:Arsslensoft/Kemlock.git`, private, checked out next to this one as
`../kemlock`, in `mobile/`) and the browser extension
([Kemlock-browser](https://github.com/Arsslensoft/Kemlock-browser), `../kemlock-browser`), which
compiles it to WebAssembly with dart2wasm. The code moves in from the app's `mobile/lib`; until it
has, `lib/kemlock_core.dart` and `test/kemlock_core_test.dart` are placeholders that the move
replaces.

## Layout

- `lib/`: the package. `lib/kemlock_core.dart` is its entry point; once the code has moved in it
  will be in `lib/src/`.
- `test/`: `package:test` tests, mirroring `lib/`. `test/fixtures/` will hold what older versions
  wrote, once it moves in with the tests.
- `docs/` (when there are notes that are part of the repo; none yet). `/plans/` holds local notes and
  stays out of git.

## Rules of the code

- **Pure Dart.** No Flutter, no `dart:ui`. Code the browser extension reaches compiles with
  dart2wasm, so it imports no `dart:io` without a conditional import. A test that needs `dart:io`
  is marked `@TestOn('vm')`.
- **Formats stay byte for byte.** What other versions or people read (the vault, exports, sync
  files, `kem1`, manifests, OPAQUE messages, the account crypto) must stay what the app wrote, or
  vaults and backups already on people's devices stop opening. A change to a format needs a
  version label and a fixture that proves the old data still opens.
- **Never regenerate or edit a fixture or a test vector.** A new one may be added next to the old
  ones.
- **Old names stay where a file or stored key carries them.** The app was called BackMyCodes until
  November 2026: `"app": "BackMyCodes"` in exports and sync files, the `backmycodes_` storage keys,
  `backmycodes-sync.json`, `backmycodes-space-<id>.json`, and the `BMCKIT1-` and `bmc-space:`
  prefixes keep their names. Don't rename those.
- `dart format` uses `analysis_options.yaml`'s page width of 140: never pass `-l`. Run
  `dart pub get` first in a new checkout or worktree.

## Checks

`dart format --output=none --set-exit-if-changed .`, `dart analyze --fatal-infos`, `dart test` and
`dart test -p chrome -c dart2wasm`, from the repository root, and
`node .github/scripts/check-licences.mjs` after `dart pub get`. On GitHub, `.github/workflows/checks.yml`
runs them as the jobs Lint, Test and Test (wasm), with Dependencies, DCO, Licences and Security
beside them. The pull request's title is checked by `title.yml`. `release.yml` calls `checks.yml`
on every push to `main` and, when it passes, tags the commit and releases the next version from the
Conventional Commits (nothing is committed for a release: the version is the tag's; the release has
no files, since the consumers pin a commit). `codeql.yml` (the workflows only: CodeQL has no Dart)
and `scorecard.yml` scan the repository. A coding agent never signs off a commit (DCO): leave that
to the person.

## Commits

Commit one change at a time. Each feature, fix, test, chore, docs change or refactor gets its own
commit; never lump unrelated work into one commit like "fix" or "refactoring".

- Messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#specification):
  `type(scope): what the change does`, in plain words, lowercase after the colon, no trailing period.
- Types: `feat`, `fix`, `test`, `chore`, `docs`, `refactor`, `revert`, plus `perf`, `ci` and
  `build` where they fit.
- The scope is the area touched: `crypto`, `models`, `vault`, `sync`, `webdav`, `vaultwarden`,
  `kemlock` (the Kemlock Server engine), `otp`, `generator`, `websites`, `deps`, `ci`, `docs`.
- A test goes in its own `test(scope)` commit, after the commit for the code it checks, unless it is
  the regression test of a fix, which goes in with the fix.
- Lockfile and dependency changes go in with the feature that needs them, or in their own commit
  titled as Dependabot's are: `fix(deps)` for a dependency the code uses (it makes a patch
  release), `chore(deps-dev)` for a development tool only, `chore(deps)` for an Action.
- The body, wrapped at about 72 columns, says what was wrong or missing and why the change fixes it.
  Name other commits by their short hash.
- AI agents end the message with an `Assisted-by: <model> via <tool>` footer, e.g.
  `Assisted-by: Claude Opus 5.5 via Claude Code`, and no `Co-Authored-By` line.
- A coding agent never adds a `Signed-off-by` line: only a person certifies the DCO.

Examples:

```text
feat(sync): retry a WebDAV upload that the server refused with 423
fix(crypto): reject a kem1 blob whose ciphertext is one byte short
test(vault): open the vault fixtures of every past version
fix(deps): update pointycastle to 4.0.1
```

To split a working tree, stage whole files, or a file's hunks with `git apply --cached` on a patch
(`git add -p` is interactive). Don't rewrite pushed history to split old commits unless asked.
