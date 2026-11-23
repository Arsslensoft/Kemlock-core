// Signed git commits and tags, as `git cat-file commit <id>` and
// `git cat-file tag <name>` print them: finding the signature in the object
// and rebuilding the bytes git signed, the way git's own `commit.c` and
// `gpg-interface.c` do.
//
// - A commit carries its signature in a `gpgsig` header (`gpgsig-sha256` in
//   a SHA-256 repository), whose further lines each start with one space.
//   What was signed is the commit without those headers.
// - A tag carries it at the end of its body. What was signed is everything
//   before the line that starts the signature block.
//
// Git signs with the namespace `git`.

import 'dart:convert';
import 'dart:typed_data';

import 'sshsig.dart';

/// The namespace git signs commits and tags for.
const gitSshsigNamespace = 'git';

/// How a commit or tag is signed.
enum GitSignatureKind {
  /// An `SSH SIGNATURE` block (`gpg.format ssh`).
  ssh,

  /// A `PGP SIGNATURE` or `PGP MESSAGE` block (git's default format).
  pgp,

  /// Another kind of block: X.509's `SIGNED MESSAGE`.
  other,

  /// No signature at all.
  unsigned,
}

/// A commit or tag taken apart.
class GitSignedObject {
  const GitSignedObject(this.kind, this.payload, [this.signature]);

  final GitSignatureKind kind;

  /// The bytes git signed: the object without its signature.
  final Uint8List payload;

  /// The armored signature block; null for [GitSignatureKind.unsigned].
  final String? signature;
}

/// [splitGitSignature] was given something that is not the raw text of a
/// commit or a tag.
class NotAGitObjectException implements Exception {
  const NotAGitObjectException();

  @override
  String toString() => 'NotAGitObjectException';
}

final _commitStart = RegExp(r'^tree [0-9a-f]{40}(?:[0-9a-f]{24})?\n');
final _tagStart = RegExp(r'^object [0-9a-f]{40}(?:[0-9a-f]{24})?\ntype [a-z]+\n');

/// The markers git knows a signature block by, and their kinds
/// (`gpg-interface.c`).
const _markers = {
  '-----BEGIN SSH SIGNATURE-----': GitSignatureKind.ssh,
  '-----BEGIN PGP SIGNATURE-----': GitSignatureKind.pgp,
  '-----BEGIN PGP MESSAGE-----': GitSignatureKind.pgp,
  '-----BEGIN SIGNED MESSAGE-----': GitSignatureKind.other,
};

GitSignatureKind _kindOf(String signature) =>
    _markers.entries.where((m) => signature.startsWith(m.key)).map((m) => m.value).firstOrNull ?? GitSignatureKind.other;

/// Takes the signature out of the raw bytes of a commit or a tag and gives
/// the bytes that were signed. White space before the object, which pasted
/// text may have, is dropped; nothing else is changed.
///
/// Throws [NotAGitObjectException] when [object] starts like neither.
GitSignedObject splitGitSignature(List<int> object) {
  // One character per byte, so positions in the text are positions in the
  // bytes, whatever the encoding of the message.
  var text = latin1.decode(object);
  text = text.substring(text.length - text.trimLeft().length);
  if (_commitStart.hasMatch(text)) return _splitCommit(text);
  if (_tagStart.hasMatch(text)) return _splitTag(text);
  throw const NotAGitObjectException();
}

GitSignedObject _splitCommit(String text) {
  final blank = text.indexOf('\n\n');
  final headerEnd = blank < 0 ? text.length : blank + 1;
  // A SHA-256 repository names its trees with 64 digits and signs in
  // `gpgsig-sha256`; a commit converted between the two carries both.
  final wanted = text.indexOf('\n') == 'tree '.length + 64 ? 'gpgsig-sha256' : 'gpgsig';
  final payload = StringBuffer();
  String? signature;
  String? fallback;
  var at = 0;
  while (at < headerEnd) {
    var end = _lineEnd(text, at, headerEnd);
    final line = text.substring(at, end);
    final name = line.startsWith('gpgsig ')
        ? 'gpgsig'
        : line.startsWith('gpgsig-sha256 ')
        ? 'gpgsig-sha256'
        : null;
    if (name == null) {
      payload.write(line);
      at = end;
      continue;
    }
    final value = StringBuffer(line.substring(name.length + 1));
    while (end < headerEnd && text[end] == ' ') {
      final next = _lineEnd(text, end, headerEnd);
      value.write(text.substring(end + 1, next));
      end = next;
    }
    if (name == wanted) {
      signature ??= value.toString();
    } else {
      fallback ??= value.toString();
    }
    at = end;
  }
  payload.write(text.substring(headerEnd));
  signature ??= fallback;
  final bytes = latin1.encode(payload.toString());
  return signature == null ? GitSignedObject(GitSignatureKind.unsigned, bytes) : GitSignedObject(_kindOf(signature), bytes, signature);
}

GitSignedObject _splitTag(String text) {
  // As git does: the last line that starts a signature block.
  int? start;
  for (var at = 0; at < text.length; at = _lineEnd(text, at, text.length)) {
    if (_markers.keys.any((m) => text.startsWith(m, at))) start = at;
  }
  if (start == null) return GitSignedObject(GitSignatureKind.unsigned, latin1.encode(text));
  final signature = text.substring(start);
  return GitSignedObject(_kindOf(signature), latin1.encode(text.substring(0, start)), signature);
}

/// The position after the line that starts at [from]: past its line ending,
/// or [limit] when it has none.
int _lineEnd(String text, int from, int limit) {
  final newline = text.indexOf('\n', from);
  return newline < 0 || newline >= limit ? limit : newline + 1;
}

/// What checking a commit or tag found.
class GitVerification {
  const GitVerification(this.kind, [this.signature, this.result]);

  /// How the object is signed. Only [GitSignatureKind.ssh] is checked.
  final GitSignatureKind kind;

  /// The SSH signature found in it, and how it stands; both null for any
  /// other [kind].
  final SshSignature? signature;
  final SshsigResult? result;
}

/// Checks the SSH signature of the raw commit or tag [object] for the
/// namespace `git`.
///
/// Pasted text often loses the final line ending `git cat-file` printed, so
/// when the bytes as given do not verify, they are tried once more with one
/// line ending added. That cannot make a changed commit good: the signature
/// still has to match one exact payload.
///
/// Throws [NotAGitObjectException], and [SshsigFormatException] when the
/// signature block in it cannot be read.
Future<GitVerification> verifyGitSignature(List<int> object) async {
  final split = splitGitSignature(object);
  if (split.kind != GitSignatureKind.ssh) return GitVerification(split.kind);
  final signature = readSshsig(split.signature!);
  var result = await sshsigVerify(signature, gitSshsigNamespace, split.payload);
  if (result.verdict == SshsigVerdict.bad) {
    final retried = await sshsigVerify(signature, gitSshsigNamespace, [...split.payload, 0x0a]);
    if (retried.isGood) result = retried;
  }
  return GitVerification(split.kind, signature, result);
}
