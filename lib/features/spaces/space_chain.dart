// A record of a space's chain (the space chain section of docs/crypto.md, version 2;
// docs/plans/add-server-spaces.md, design 2). Every change to who is in a space, their roles,
// grants, policies and keys is a record, signed by the member who made it and linked to the
// record before, so no server can add a member, widen a grant or quietly undo a removal.
//
//   {"at","body","by","epoch","kind","prev","seq","space","v":1}
//
// written in the strict subset of JSON of `chain_json.dart`, which is its own RFC 8785 (JCS)
// serialisation without whitespace, so it has exactly one spelling:
//
// - binary values are base64url without padding and ids are hyphenated lower-case UUIDs;
//   `space` is the space's server UUID (the legacy-id UUID for a moved WebDAV space);
// - `prev` is the link of the previous record, `link(record) = SHA-256("kemlock/v1/space-chain/link"
//   || record bytes)`, 32 zero bytes for `seq` 0. The link covers the record's bytes only, never a
//   signature;
// - `epoch` is the space's home epoch (docs/federation.md), `at` is Unix seconds for display and
//   `by` the account id of the signer;
// - the record is signed with the signer's `sig1` key under the context "space-chain", so the signed
//   message is `"kemlock/v1/sig1" || lp("space-chain") || lp(record bytes)`. A signature made for
//   another context, a bundle, a manifest or a confirmation, never verifies as a record.
//
// A signed record travels as its exact bytes in base64url with the signature beside it, never
// re-encoded, as crypto.md "Wire forms of signed structures" says; a `rekey` also carries the
// `cosignature` of the bundle it installs.
//
// The classes keep the code's word for a record, "entry".
//
// server: to confirm
// The spec's vectors (`test-vectors/space-chain.json`) are not generated yet. Until they are, the
// two link examples of the spec, computed by hand, are the only known answers.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../crypto/account/bundle.dart';
import '../../crypto/account/confirm.dart' as confirm;
import '../../crypto/account/encoding.dart';
import '../../crypto/account/jcs.dart';
import '../../crypto/account/kx1.dart' show Kx1;
import '../../crypto/account/sig1.dart';
import '../../crypto/bytes.dart' show concatBytes, constantTimeEquals;
import 'chain_body.dart' show validateBody;
import 'chain_json.dart';
import 'chain_kind.dart';

export 'chain_kind.dart';

/// The version every entry carries.
const spaceChainVersion = 1;

/// The label the link of a record is hashed under.
const chainLinkLabel = 'kemlock/v1/space-chain/link';

/// The most bytes a record has, 192 KiB.
const maxChainRecordBytes = 196608;

/// The most records a chain has, and the most bytes of records.
///
/// owner: to decide
/// What happens past these limits is the owner's: the spec's options are a checkpoint record, a new space and a move,
/// or a higher limit with incremental verification. None is built; a chain beyond them is refused as too large.
const maxChainRecords = 65536;
const maxChainBytes = 64 * 1024 * 1024;

/// The highest `seq`.
const maxChainSeq = maxChainRecords - 1;

/// The `prev` of the first entry: 32 zero bytes.
Uint8List get chainGenesisLink => Uint8List(32);

/// One entry of a space's chain, without its signature.
final class SpaceChainEntry {
  SpaceChainEntry({
    required this.space,
    required this.seq,
    required List<int> prev,
    required this.epoch,
    required this.at,
    required this.by,
    required this.kind,
    required Map<String, Object?> body,
  }) : prev = copyBytes(requireLength(prev, 32, 'a chain link')),
       body = Map.unmodifiable(body) {
    uuidBytes(space);
    uuidBytes(by);
    if (seq < 0 || seq > maxChainSeq) {
      throw MalformedException('a sequence number is from 0 to $maxChainSeq: $seq');
    }
    if (epoch < 1 || epoch > 0xffffffff) {
      throw MalformedException('an epoch is from 1 to 2^32 - 1: $epoch');
    }
    if (at < 0 || at > chainMaxInteger) {
      throw MalformedException('a time is from 0 to 2^53 - 1: $at');
    }
  }

  /// Reads the JSON object. An unknown member, an unknown version or kind, a number that isn't a whole
  /// number, an id that isn't a hyphenated lower-case UUID and base64url that isn't canonical are a
  /// [MalformedException].
  factory SpaceChainEntry.fromJson(Object? json) {
    final fields = strictObject(json, required: {'v', 'space', 'seq', 'prev', 'epoch', 'at', 'by', 'kind', 'body'});
    if (fields['v'] != spaceChainVersion) {
      throw MalformedException('unknown chain version ${fields['v']}');
    }
    String string(String name) {
      final value = fields[name];
      if (value is! String) {
        throw MalformedException('$name is a string');
      }
      return value;
    }

    int integer(String name) {
      final value = fields[name];
      if (value is! int) {
        throw MalformedException('$name is a whole number');
      }
      return value;
    }

    final kind = ChainKind.fromWire(string('kind'));
    if (kind == null) {
      throw MalformedException('unknown chain entry kind ${fields['kind']}');
    }
    final body = fields['body'];
    if (body is! Map<String, Object?>) {
      throw const MalformedException('body is an object');
    }
    validateBody(kind, body);
    return SpaceChainEntry(
      space: string('space'),
      seq: integer('seq'),
      prev: b64urlDecode(string('prev')),
      epoch: integer('epoch'),
      at: integer('at'),
      by: string('by'),
      kind: kind,
      body: body,
    );
  }

  /// Reads the exact bytes an entry was signed over. Anything but the RFC 8785 serialisation of an entry, in the
  /// strict subset of `chain_json.dart`, is a [MalformedException], so a signature always covers the canonical
  /// bytes and no entry has two spellings. More than 192 KiB is a [ChainRefusal] of [ChainProblem.tooLarge].
  factory SpaceChainEntry.parse(List<int> bytes) {
    if (bytes.length > maxChainRecordBytes) {
      throw ChainRefusal(ChainProblem.tooLarge, 'a record is at most $maxChainRecordBytes bytes, not ${bytes.length}');
    }
    final entry = SpaceChainEntry.fromJson(readChainJson(bytes));
    if (!constantTimeEquals(entry.bytes, bytes)) {
      throw const MalformedException('a chain entry is its RFC 8785 bytes');
    }
    return entry;
  }

  /// The space's UUID.
  final String space;
  final int seq;

  /// The link of the previous entry, or [chainGenesisLink].
  final Uint8List prev;

  /// The space's home epoch the entry was made under.
  final int epoch;

  /// Unix seconds.
  final int at;

  /// The signer's account id, a UUID.
  final String by;
  final ChainKind kind;

  /// What the kind sets, JSON.
  final Map<String, Object?> body;

  Map<String, Object?> toJson() => {
    'v': spaceChainVersion,
    'space': space,
    'seq': seq,
    'prev': b64urlEncode(prev),
    'epoch': epoch,
    'at': at,
    'by': by,
    'kind': kind.wire,
    'body': body,
  };

  /// The bytes that are signed and hashed: [toJson] as RFC 8785.
  Uint8List get bytes => jcsBytes(toJson());

  /// The link of this entry, `SHA-256("kemlock/v1/space-chain/link" || bytes)`, which the next entry's `prev`
  /// holds. The unlabelled hash of the bytes is not a link.
  Uint8List get hashed => Uint8List.fromList(hash.sha256.convert(concatBytes([label(chainLinkLabel), bytes])).bytes);
}

// The wire form is the server's, pinned in the space chain section of docs/crypto.md; the exact bytes and the signature
// beside them are crypto.md's form for every signed structure.
/// An entry with its `sig1` signature, as the server serves it and a device stores it. A `rekey` also holds the
/// [cosignature] of the bundle it installs, and no other kind does ([SignedChainEntry.fromJson] refuses the rest).
final class SignedChainEntry {
  SignedChainEntry(this.entry, List<int> signature, {List<int>? cosignature})
    : signature = copyBytes(requireLength(signature, Sig1.signatureLength, 'a chain entry signature')),
      cosignature = cosignature == null ? null : copyBytes(requireLength(cosignature, Sig1.signatureLength, 'a chain entry cosignature'));

  /// Reads `{"entry": <base64url of the entry's bytes>, "signature": <base64url>}`, with a `"cosignature"` as a
  /// third member for a `rekey` and only for it. The bytes must be the entry's canonical ones.
  factory SignedChainEntry.fromJson(Object? json) {
    final fields = strictObject(json, required: {'entry', 'signature'}, optional: {'cosignature'});
    final entry = fields['entry'];
    final signature = fields['signature'];
    final cosignature = fields['cosignature'];
    if (entry is! String || signature is! String || (fields.containsKey('cosignature') && cosignature is! String)) {
      throw const MalformedException('entry, signature and cosignature are base64url strings');
    }
    final signed = SignedChainEntry(
      SpaceChainEntry.parse(b64urlDecode(entry)),
      b64urlDecode(signature),
      cosignature: cosignature is String ? b64urlDecode(cosignature) : null,
    );
    if ((signed.entry.kind == ChainKind.rekey) != (signed.cosignature != null)) {
      throw const MalformedException('a cosignature is carried by a rekey, and by no other kind');
    }
    return signed;
  }

  final SpaceChainEntry entry;
  final Uint8List signature;

  /// The signature by the key of the bundle a `rekey` installs, or null.
  final Uint8List? cosignature;

  Map<String, Object?> toJson() => {
    'entry': b64urlEncode(entry.bytes),
    'signature': b64urlEncode(signature),
    if (cosignature != null) 'cosignature': b64urlEncode(cosignature!),
  };
}

/// Reads a chain as the server serves it: a JSON array of signed entries in ascending `seq`. These are the checks of
/// step 0 of verification: more than 65,536 entries or 64 MiB of entry bytes is [ChainProblem.tooLarge], and an
/// element that isn't a signed entry of canonical bytes is [ChainProblem.malformed]. If any element fails the whole
/// chain is refused, before any entry is applied, and the refusal names the position of the first element that failed
/// ([ChainRefusal.index]).
List<SignedChainEntry> parseChain(Object? json) {
  if (json is! List<Object?>) {
    throw const ChainRefusal(ChainProblem.malformed, 'a chain is an array');
  }
  if (json.length > maxChainRecords) {
    throw ChainRefusal(ChainProblem.tooLarge, 'a chain is at most $maxChainRecords records, not ${json.length}');
  }
  final signed = <SignedChainEntry>[];
  var bytes = 0;
  for (var index = 0; index < json.length; index++) {
    final SignedChainEntry read;
    try {
      read = SignedChainEntry.fromJson(json[index]);
    } on MalformedException catch (e) {
      throw ChainRefusal(ChainProblem.malformed, e.message, index: index);
    } on ChainRefusal catch (e) {
      throw ChainRefusal(e.problem, e.detail, index: index);
    }
    bytes += read.entry.bytes.length;
    if (bytes > maxChainBytes) {
      throw ChainRefusal(ChainProblem.tooLarge, 'a chain is at most 64 MiB of records', index: index);
    }
    signed.add(read);
  }
  return signed;
}

/// Signs [entry] with the signer's `sig1` private key under the context "space-chain".
Future<SignedChainEntry> signChainEntry(SpaceChainEntry entry, Uint8List sig1PrivateKey) async =>
    SignedChainEntry(entry, await Sig1.sign(sig1PrivateKey, entry.bytes, context: SignContext.spaceChain));

/// Whether [signed]'s signature is by [signerPublicKey] under the context "space-chain", and no other.
Future<bool> verifyChainEntry(SignedChainEntry signed, Uint8List signerPublicKey) =>
    Sig1.verify(signerPublicKey, signed.entry.bytes, signed.signature, context: SignContext.spaceChain);

/// The signature checks a chain's verification makes, so a test can put cheap signatures in place of `sig1`'s,
/// which are slow in pure Dart. [RealChainCrypto] is the production one.
abstract interface class ChainCrypto {
  /// Whether [signature] is [signerPublicKey]'s signature of the entry bytes [entryBytes], under "space-chain".
  Future<bool> checkEntry(Uint8List signerPublicKey, Uint8List entryBytes, Uint8List signature);

  /// Whether [signature] is [bundle]'s own signature of itself.
  Future<bool> checkBundle(KeyBundle bundle, Uint8List signature);

  /// Whether [signature] is the confirmer's signature of [statement] under "confirm".
  Future<bool> checkConfirmation(Uint8List statement, Uint8List signature, Uint8List confirmerPublicKey);

  /// Whether [key] is a usable recovery key: its ML-KEM-1024 half passes FIPS 203's encapsulation-key check and a trial
  /// `kx1` encapsulation to it succeeds, which refuses a low-order X25519 half.
  Future<bool> checkRecoveryKey(Uint8List key);
}

/// [ChainCrypto] with `sig1`.
final class RealChainCrypto implements ChainCrypto {
  const RealChainCrypto();

  @override
  Future<bool> checkEntry(Uint8List signerPublicKey, Uint8List entryBytes, Uint8List signature) =>
      Sig1.verify(signerPublicKey, entryBytes, signature, context: SignContext.spaceChain);

  @override
  Future<bool> checkBundle(KeyBundle bundle, Uint8List signature) => verifyBundle(bundle, signature);

  @override
  Future<bool> checkConfirmation(Uint8List statement, Uint8List signature, Uint8List confirmerPublicKey) async {
    try {
      await confirm.verifyConfirmation(statement, signature, confirmerPublicKey);
      return true;
    } on CorruptedException {
      return false;
    } on MalformedException {
      return false;
    }
  }

  @override
  Future<bool> checkRecoveryKey(Uint8List key) async {
    try {
      final made = await Kx1.encapsulate(key);
      wipe(made.sharedSecret);
      return true;
    } on MalformedException {
      return false;
    }
  }
}
