# Contributing

Thanks for helping out!

This repository is Kemlock-core, the pure-Dart code that the Kemlock app and the Kemlock browser
extension share: the crypto, the vault, the sync engines, OTP, the password generator and site
matching. Open an issue or a pull request on
[Arsslensoft/Kemlock-core](https://github.com/Arsslensoft/Kemlock-core). By taking part you agree
to the [Code of Conduct](CODE_OF_CONDUCT.md). A security problem is not an issue: see
[SECURITY.md](SECURITY.md).

Set up with `dart pub get`. Dart 3.13.5 is what the checks run with (the Flutter version the app
uses ships it).

## Two rules before the rest

- **Byte formats stay what they are.** The vault, exports, sync files, `kem1`, manifests, OPAQUE
  messages and account crypto are read by other versions of Kemlock and by vaults already on
  people's devices. A change that alters one needs a version label for the new format and a fixture
  that proves data written by the old one still opens. The test vectors and fixtures in `test/fixtures/` are never
  regenerated or edited; a new one may be added.
- **Pure Dart.** No Flutter, no `dart:ui`. The browser extension compiles this package to
  WebAssembly with dart2wasm, so code it reaches does not import `dart:io` without a conditional
  import. A test tagged `wasm` (`@Tags(['wasm'])`) runs there too, with `dart test -p chrome -c
  dart2wasm -t wasm`; every other test reads its fixtures with `dart:io` and is marked
  `@TestOn('vm')`.

## Pull requests

The `main` ruleset requires a pull request, with no approvals needed, the checks below, and every
conversation resolved. CodeRabbit reviews each pull request, and the maintainer merges it; the
maintainer can bypass the ruleset. The required checks are these jobs, under the names GitHub
shows:

- **Lint**: `dart format --output=none --set-exit-if-changed .` (the page width is 140, from
  `analysis_options.yaml`; `dart format .` fixes the formatting), `dart analyze --fatal-infos`,
  ShellCheck on the shell files you changed, and actionlint on the workflows.
- **Test**: `dart test` on the Dart VM.
- **Test (wasm)**: `dart test -p chrome -c dart2wasm`, the same tests compiled to WebAssembly and
  run in Chrome, as the browser extension runs the code. A test that needs `dart:io` is marked
  `@TestOn('vm')` and is left out here.
- **Title** (its own workflow, `title.yml`): the title is a Conventional Commit
  (`fix(vault): ...`), since it becomes the commit's subject when the pull request is squashed,
  and a `feat` or a `fix` becomes a line of the release's notes. Write it in plain words.
- **Dependencies**: nothing the change adds has a known serious vulnerability or a licence that
  GPL-3.0-or-later cannot take in.
- **DCO**: every commit is signed off (below). `bash .github/scripts/check-dco.sh origin/main HEAD`
  runs it on your machine.
- **Licences**: every package pub resolves, the development tools as well as what the apps build
  with, is under a licence on the list in `.github/scripts/check-licences.mjs`. After
  `dart pub get`, `node .github/scripts/check-licences.mjs` runs it on your machine. A package
  without a licence file, or with one the script cannot tell, is named in
  `.github/licence-exceptions.json`, with its licence and why, once a person has read it.
- **Security**: the change adds no workflow risk that `zizmor` finds and `main` does not have, no
  secret in its commits (`gitleaks`; a made-up one in a test is fine, elsewhere mark its line with
  `gitleaks:allow`), and, when it changes `pubspec.lock`, no package with a known advisory
  (`osv-scanner scan source --config osv-scanner.toml --lockfile pubspec.lock`). An advisory
  against a package that `main` already has does not block other pull requests. One that has no
  fix yet is set aside in `osv-scanner.toml`, in a `[[IgnoredVulns]]` block with its `id`, an
  `ignoreUntil` date (a few months out, so that it is looked at again) and a `reason` that says
  why this package is not affected or what the fix is waiting for. Say so in the pull request.

CodeRabbit reviews every push. Answer or fix each of its comments and resolve the thread; its
checks (the licences and credits, a test with every change of behaviour, the crypto and format
safety, the documentation kept accurate) are open until they are settled. CodeQL scans the
workflows (it does not support Dart, so the analyzer holds the code).

### Signing off (DCO)

Each commit carries a `Signed-off-by:` line with your name and the address you commit with, by
which you certify the [Developer Certificate of Origin](https://developercertificate.org): that you
wrote the change, or otherwise have the right to submit it under the project's licence.
`git commit -s` adds it; for commits made already, `git rebase --signoff origin/main` and push
again. Only a person can certify it: a coding agent never signs off for you, so sign off its
commits yourself once you have read them. A bot's commits (Dependabot's) are passed over.

## Commits

One change at a time, as [CLAUDE.md](CLAUDE.md) says: Conventional Commits,
`type(scope): what the change does`, lowercase after the colon, no trailing period, a body that
says what was wrong and why the change fixes it, and a test in its own commit or with its fix.
End the message with `Assisted-by: <model> via <tool>` when an AI agent helped.

## Releases

Nobody makes a release by hand. A push to main that holds a `feat`, a `fix`, a `perf` or a `revert`
commit since the last tag is tagged and released as the next version, which the commit types decide
(README.md, Releases). Nothing is committed for it: the version is the tag's. A release has no
files: the app and the extension pin a commit, which the release's notes give.

## Dependencies

Dependabot proposes updates every week. It turns on auto-merge for a patch update of any
dependency, and for a minor update of a development dependency or of a GitHub Action; they merge
once the required checks pass. A major update, and a minor one of a package the code uses, wait
for a person. An update of a package the code uses is titled `fix(deps): ...`, so it makes a patch
release; one of a development tool or an Action is `chore`, and makes none.

This package's constraints match the app's, so that the app's lockfile resolves one version of each
package. When you change a dependency here, check that the app and the extension still resolve.
