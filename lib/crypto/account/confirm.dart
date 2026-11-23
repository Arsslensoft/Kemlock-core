// The member confirmation of `docs/crypto.md` "Member confirmation": a
// space hands its keys only to a member that someone already in the space
// confirmed. The confirmer compared the member's fingerprint with the one on
// the member's own screen, and signs that they did:
//
//   statement = "kemlock/v1/confirm" || space id (16) || member id (16)
//               || u32be(member key version) || fingerprint (64) || confirmer id (16)
//   signature = sig1 signature by the confirmer's own key, context "confirm"
//
// The statement is 134 bytes and the signature 3373. The fingerprint is the
// member's bundle fingerprint (bundle.dart) that the confirmer compared, and
// the key version is the member's key version of that bundle, so a
// confirmation stops covering a member whose account later moves to a new key
// version. The server keeps the pair beside the member and every other
// member's client verifies it again against the confirmer's bundle.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../bytes.dart';
import 'bundle.dart';
import 'encoding.dart';
import 'sig1.dart';

const _confirmLabel = 'kemlock/v1/confirm';

/// What a confirmer signs: that they compared this member's fingerprint.
final class ConfirmStatement {
  ConfirmStatement({
    required List<int> space,
    required List<int> member,
    required this.memberKeyVersion,
    required List<int> fingerprint,
    required List<int> confirmer,
  }) : space = copyBytes(requireLength(space, 16, 'a space id')),
       member = copyBytes(requireLength(member, 16, 'a member id')),
       fingerprint = copyBytes(requireLength(fingerprint, 64, 'a fingerprint')),
       confirmer = copyBytes(requireLength(confirmer, 16, 'a confirmer id')) {
    u32be(memberKeyVersion); // range check
  }

  /// The statement for [member]'s [bundle]: its account id, key version and fingerprint.
  factory ConfirmStatement.forBundle({required List<int> space, required KeyBundle bundle, required List<int> confirmer}) =>
      ConfirmStatement(
        space: space,
        member: bundle.accountId,
        memberKeyVersion: bundle.keyVersion,
        fingerprint: bundle.fingerprint,
        confirmer: confirmer,
      );

  /// Reads the 134 bytes. A wrong label or length, or trailing bytes, are a [MalformedException].
  factory ConfirmStatement.parse(List<int> bytes) {
    final reader = ByteReader(bytes);
    final prefix = label(_confirmLabel);
    if (!constantTimeEquals(reader.read(prefix.length, 'the statement label'), prefix)) {
      throw const MalformedException('not a confirmation statement');
    }
    final space = reader.read(16, 'the space id');
    final member = reader.read(16, 'the member id');
    final keyVersion = reader.readU32('the member key version');
    final fingerprint = reader.read(64, 'the fingerprint');
    final confirmer = reader.read(16, 'the confirmer id');
    reader.finish();
    return ConfirmStatement(space: space, member: member, memberKeyVersion: keyVersion, fingerprint: fingerprint, confirmer: confirmer);
  }

  /// The length of every statement.
  static const length = 18 + 16 + 16 + 4 + 64 + 16;

  final Uint8List space;
  final Uint8List member;
  final int memberKeyVersion;
  final Uint8List fingerprint;
  final Uint8List confirmer;

  /// The bytes that are signed.
  Uint8List get bytes => concatBytes([label(_confirmLabel), space, member, u32be(memberKeyVersion), fingerprint, confirmer]);

  /// Whether the statement is about [bundle]: its account, its key version and its fingerprint.
  bool covers(KeyBundle bundle) =>
      constantTimeEquals(member, bundle.accountId) &&
      memberKeyVersion == bundle.keyVersion &&
      fingerprintsMatch(fingerprint, bundle.fingerprint);
}

/// The confirmer's signature of [statement] with their `sig1` private key, under the context "confirm".
Future<Uint8List> signConfirmation(ConfirmStatement statement, Uint8List confirmerSig1PrivateKey) =>
    Sig1.sign(confirmerSig1PrivateKey, statement.bytes, context: SignContext.confirm);

/// Reads [statementBytes] and returns the statement only when [signature] is a valid `sig1` signature of it
/// by [confirmerPublicKey] under the context "confirm". A statement that is malformed is a
/// [MalformedException]; one whose signature does not verify is a [CorruptedException].
Future<ConfirmStatement> verifyConfirmation(List<int> statementBytes, Uint8List signature, Uint8List confirmerPublicKey) async {
  final statement = ConfirmStatement.parse(statementBytes);
  if (!await Sig1.verify(confirmerPublicKey, statementBytes, signature, context: SignContext.confirm)) {
    throw const CorruptedException('the confirmation signature does not verify');
  }
  return statement;
}
