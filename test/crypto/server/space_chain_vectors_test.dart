// The 53 chains verify ML-DSA-65 signatures in pure Dart, which takes longer than the default 30 seconds
@Timeout(Duration(minutes: 15))
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sealed_box.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/crypto/bytes.dart' show concatBytes;
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_chain_client.dart' show chainProblemOf;
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:kemlock_core/features/spaces/space_seals.dart';
import 'package:kemlock_core/features/spaces/space_types.dart';
import 'package:kemlock_core/features/spaces/space_verify.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's space-chain.json (crypto.md, "Space chain"), in five kinds of case, by `type`:
//
// - `link`: the labelled hash of a record's bytes, which is its link, and not the unlabelled one;
// - `encoding`: records a reader must refuse as malformed, each with its `reason`;
// - `signing`: the signing input of a record and its signature under "space-chain", and no other context;
// - `seals`: the commitments of a key version: seal hash, digest and key check, and each recipient's box, opened with
//   its context and aad;
// - `chain`: chains of records, each with the verdict a verifier must give: accepted with the head, or refused with
//   the reason and the seq of the record. A chain with a `base` starts with `prefix` records of that case's chain; one
//   with an `anchor` is verified against it.
//
// Binary values are lower-case hex, except `record` and `link_b64url`, which are text. A record of a chain travels as
// its exact bytes (`entry`) with its `signature` and, for a rekey, its `cosignature`; `parseChain` reads them in
// base64url. Account, space and collection ids are 16 bytes in hex, which this test writes as UUIDs.
//
// The server names a refusal by words ("bad link"); `problems` gives each one's [ChainProblem], without the app's own
// spelling rules (`chainProblemOf`), which a test below holds to the same words.
void main() {
  const file = 'space-chain.json';
  final cases = readServerCases(file);

  const problems = {
    'malformed': ChainProblem.malformed,
    'too large': ChainProblem.tooLarge,
    'wrong space': ChainProblem.wrongSpace,
    'bad sequence': ChainProblem.badSequence,
    'bad link': ChainProblem.badLink,
    'bad epoch': ChainProblem.badEpoch,
    'unknown signer': ChainProblem.unknownSigner,
    'bad signature': ChainProblem.badSignature,
    'bad bundle': ChainProblem.badBundle,
    'bad confirmation': ChainProblem.badConfirmation,
    'invalid': ChainProblem.invalid,
    'not allowed': ChainProblem.notAllowed,
    'forked': ChainProblem.forked,
    'rolled back': ChainProblem.rolledBack,
  };

  // The wrong contexts of the signing case, as the app names them
  const contexts = {'bundle': SignContext.bundle, 'manifest': SignContext.manifest, 'confirm': SignContext.confirm};

  ChainProblem problemOf(Object? reason) {
    final problem = problems[reason];
    if (problem == null) {
      throw FormatException('a reason the app has no problem for: $reason');
    }
    return problem;
  }

  /// A hex field as base64url, the form `parseChain` reads.
  String wire(Object? hex, String field) {
    if (hex is! String) {
      throw FormatException('the case has no hex field $field');
    }
    return b64urlEncode(fromHex(hex));
  }

  /// The 16 bytes of an id in hex as the UUID the app writes it as.
  String uuidOf(Object? hex) => uuidText(fromHex(hex! as String));

  List<Map<String, Object?>> ofType(String type) => [
    for (final c in cases)
      if (c['type'] == type) c,
  ];

  final chains = {for (final c in ofType('chain')) c['name']! as String: c};

  /// The records of a chain case: the first `prefix` of its base's, then its own.
  List<Map<String, Object?>> recordsOf(Map<String, Object?> c) {
    final own = objects(c['records']);
    final base = c['base'] as String?;
    final prefix = c['prefix'] as int?;
    if (base == null) {
      if (prefix != null) {
        throw FormatException('${c['name']} has a prefix and no base');
      }
      return own;
    }
    final shared = chains[base];
    if (shared == null || prefix == null) {
      throw FormatException('${c['name']} has the base $base and the prefix $prefix');
    }
    final head = recordsOf(shared);
    if (prefix > head.length) {
      throw FormatException('${c['name']} takes $prefix records of $base, which has ${head.length}');
    }
    return [...head.take(prefix), ...own];
  }

  /// The signature checks of the app, each made once: the cases share the records of their base chain, and a pure Dart
  /// `sig1` verification is slow.
  final crypto = _OnceChainCrypto(const RealChainCrypto());

  test('the file has cases of each kind, and no other', () {
    for (final type in ['link', 'encoding', 'signing', 'seals', 'chain']) {
      expect(ofType(type), isNotEmpty, reason: type);
    }
    expect(cases.every((c) => const {'link', 'encoding', 'signing', 'seals', 'chain'}.contains(c['type'])), isTrue);
  });

  test("the app reads the server's refusal words as its own problems", () {
    for (final entry in problems.entries) {
      expect(chainProblemOf(entry.key), entry.value, reason: entry.key);
    }
  });

  group('link', () {
    for (final c in ofType('link')) {
      final name = c['name']! as String;
      final bytes = utf8.encode(c['record']! as String);

      test('$name: the link is SHA-256 of the label and the record, and the unlabelled hash is not a link', () {
        expect(toHex(bytes), c['record_hex'], reason: 'record_hex is the record as UTF-8');
        final entry = SpaceChainEntry.parse(bytes);
        expect(entry.bytes, bytes, reason: 'the record is its own canonical bytes');
        expect(chainLinkLabel, 'kemlock/v1/space-chain/link');
        expect(toHex(entry.hashed), c['link']);
        expect(b64urlEncode(entry.hashed), c['link_b64url']);
        expect(toHex(hash.sha256.convert(concatBytes([label(chainLinkLabel), bytes])).bytes), c['link']);
        final unlabelled = hash.sha256.convert(bytes).bytes;
        expect(toHex(unlabelled), c['unlabelled_sha256']);
        expect(toHex(entry.hashed), isNot(toHex(unlabelled)));
      });
    }

    test('the second example follows the first: its prev is the first one\'s link', () {
      final links = {for (final c in ofType('link')) c['name']! as String: c};
      final fence = SpaceChainEntry.parse(utf8.encode(links['spec-fence-example']!['record']! as String));
      final role = SpaceChainEntry.parse(utf8.encode(links['spec-role-example']!['record']! as String));
      expect(role.prev, fence.hashed);
      expect(role.seq, fence.seq + 1);
    });
  });

  group('encoding', () {
    for (final c in ofType('encoding')) {
      final name = c['name']! as String;
      final reason = c['reason']! as String;
      final bytes = utf8.encode(c['record']! as String);

      test('$name: refused as $reason', () {
        final problem = problemOf(reason);
        // The reader of one record
        if (problem == ChainProblem.malformed) {
          expect(() => SpaceChainEntry.parse(bytes), throwsA(isA<MalformedException>()), reason: name);
        }
        // And the reader of a served chain, which refuses all of it at the first record that fails
        final served = [
          {'entry': b64urlEncode(bytes), 'signature': b64urlEncode(Uint8List(Sig1.signatureLength))},
        ];
        expect(
          () => parseChain(served),
          throwsA(isA<ChainRefusal>().having((e) => e.problem, 'problem', problem).having((e) => e.index, 'index', 0)),
          reason: name,
        );
      });
    }
  });

  group('signing', () {
    for (final c in ofType('signing')) {
      final name = c['name']! as String;
      final publicKey = fromHex(c['public_key']! as String);
      final record = fromHex(c['record']! as String);
      final signature = fromHex(c['signature']! as String);
      final signingInput = fromHex(c['signing_input']! as String);
      final prefix = fromHex(c['signing_input_prefix']! as String);

      test('$name: the signing input is "kemlock/v1/sig1" || lp("space-chain") || lp(record)', () {
        expect(prefix, concatBytes([label('kemlock/v1/sig1'), lp(label(SignContext.spaceChain))]));
        expect(signingInput, concatBytes([prefix, lp(record)]));
        expect(SpaceChainEntry.parse(record).bytes, record, reason: 'the signed record is a canonical one');
      });

      test('$name: the signature verifies as a record signature, and under no other context', () async {
        final signed = SignedChainEntry(SpaceChainEntry.parse(record), signature);
        expect(await verifyChainEntry(signed, publicKey), isTrue);
        expect(await Sig1.verify(publicKey, record, signature, context: SignContext.spaceChain), isTrue);
        for (final wrong in (c['wrong_contexts']! as List<Object?>).cast<String>()) {
          final context = contexts[wrong];
          expect(context, isNotNull, reason: 'the app has no context $wrong');
          expect(await Sig1.verify(publicKey, record, signature, context: context!), isFalse, reason: wrong);
        }
      });
    }
  });

  group('seals', () {
    for (final c in ofType('seals')) {
      final name = c['name']! as String;
      final space = uuidOf(c['space']);
      final ref = KeyRef.parse(c['key']! as String);
      final version = c['version']! as int;
      final secret = fromHex(c['secret']! as String);
      final recipients = objects(c['recipients']);

      test('$name: the key check is the key\'s HKDF under the space, the key and the version', () {
        expect(secret, hasLength(32));
        expect(toHex(keyCheckOf(key: secret, space: space, ref: ref, version: version)), c['check']);
      });

      test('$name: the seal hash of each box is its SHA-256, and the digest covers them in order of account', () {
        expect(recipients, isNotEmpty);
        for (final r in recipients) {
          expect(toHex(sealHashOf(fromHex(r['box']! as String))), r['seal_hash'], reason: 'the box of ${r['member']}');
        }
        final digest = sealsDigest(
          space: space,
          key: ref,
          version: version,
          recipients: [
            for (final r in recipients)
              (account: uuidOf(r['member']), bundleVersion: r['bundle_version']! as int, sealHash: fromHex(r['seal_hash']! as String)),
          ],
        );
        expect(toHex(digest), c['digest']);
        // In any order: the digest sorts them
        final reversed = sealsDigest(
          space: space,
          key: ref,
          version: version,
          recipients: [
            for (final r in recipients.reversed)
              (account: uuidOf(r['member']), bundleVersion: r['bundle_version']! as int, sealHash: fromHex(r['seal_hash']! as String)),
          ],
        );
        expect(toHex(reversed), c['digest']);
      });

      for (final r in recipients) {
        final member = uuidOf(r['member']);
        final context = r['context']! as String;

        test('$name: the box to $member has the context and aad of the app, and opens to the key', () async {
          expect(context, ref.isSpace ? SealContext.spaceKey : SealContext.collectionKey);
          final aad = ref.isSpace
              ? spaceKeyAad(space: space, keyVersion: version, member: member)
              : collectionKeyAad(space: space, collection: ref.collection!, keyVersion: version, member: member);
          expect(toHex(aad), r['aad']);
          final privateKey = fromHex(r['kx1_private_key']! as String);
          final box = fromHex(r['box']! as String);
          expect(await openBox(box, privateKey, context: context, aad: fromHex(r['aad']! as String)), secret);
          final opened = ref.isSpace
              ? await openSpaceKey(box: box, kx1PrivateKey: privateKey, space: space, keyVersion: version, member: member)
              : await openCollectionKey(
                  box: box,
                  kx1PrivateKey: privateKey,
                  space: space,
                  collection: ref.collection!,
                  keyVersion: version,
                  member: member,
                );
          expect(opened, secret);
        });
      }
    }
  });

  group('chain', () {
    for (final c in ofType('chain')) {
      final name = c['name']! as String;
      final description = c['description']! as String;
      final space = c['space']! as String;
      final expected = c['expect']! as Map<String, Object?>;
      final verdict = expected['verdict']! as String;
      final anchorJson = c['anchor'] as Map<String, Object?>?;
      final records = recordsOf(c);

      test('$name: $verdict${verdict == 'refused' ? ' as ${expected['reason']} at ${expected['seq']}' : ''}', () async {
        final ChainAnchor? anchor;
        if (anchorJson == null) {
          anchor = null;
        } else {
          final links = [for (final link in (anchorJson['links']! as List<Object?>).cast<String>()) fromHex(link)];
          expect(anchorJson['seq'], links.length - 1, reason: 'the anchor holds a link for each seq up to its own');
          anchor = ChainAnchor(epoch: anchorJson['epoch']! as int, links: links);
        }

        ChainRefusal? unread;
        ChainResult? result;
        try {
          final entries = parseChain([
            for (final record in records)
              {
                'entry': wire(record['entry'], 'entry'),
                'signature': wire(record['signature'], 'signature'),
                if (record['cosignature'] != null) 'cosignature': wire(record['cosignature'], 'cosignature'),
              },
          ]);
          result = await verifyChain(space: space, entries: entries, anchor: anchor, crypto: crypto);
        } on ChainRefusal catch (e) {
          // Refused before any record is applied, as malformed or too large: the whole chain, at one record
          unread = e;
        }

        switch (verdict) {
          case 'accepted':
            expect(unread, isNull, reason: '$name ($description) was refused before it was applied: $unread');
            final ok = result!;
            expect(ok.ok, isTrue, reason: '$name ($description) was refused as ${ok.problem?.name} at ${ok.problemSeq}: ${ok.detail}');
            expect(ok.state.headSeq, expected['head_seq'], reason: name);
            expect(toHex(ok.state.headHash!), expected['head_link'], reason: name);
            expect(toHex(ok.accepted.last.entry.hashed), expected['head_link'], reason: name);
            expect(ok.droppedFrom, expected['divergence'], reason: '$name: the records of the device the fence drops start here');
          case 'refused':
            final problem = problemOf(expected['reason']);
            if (unread != null) {
              expect(unread.problem, problem, reason: '$name ($description): ${unread.detail}');
              expect(unread.index, expected['seq'], reason: '$name: the record that could not be read');
            } else {
              final refused = result!;
              expect(refused.problem, problem, reason: '$name ($description): ${refused.detail}, at ${refused.problemSeq}');
              expect(refused.problemSeq, expected['seq'], reason: '$name ($description): ${refused.detail}');
            }
          default:
            fail('$name: the app has no verdict $verdict');
        }
      });
    }
  });
}

/// [ChainCrypto] that asks [_inner] once of each distinct question, and answers a repeat with the same answer: the
/// chains of the file share the records of their base, which would otherwise be verified again for each.
final class _OnceChainCrypto implements ChainCrypto {
  _OnceChainCrypto(this._inner);

  final ChainCrypto _inner;
  final _answers = <String, Future<bool>>{};

  Future<bool> _once(String question, List<List<int>> parts, Future<bool> Function() ask) {
    final key = hash.sha256.convert(concatBytes([label(question), for (final part in parts) lp(part)])).toString();
    return _answers.putIfAbsent(key, ask);
  }

  @override
  Future<bool> checkEntry(Uint8List signerPublicKey, Uint8List entryBytes, Uint8List signature) =>
      _once('entry', [signerPublicKey, entryBytes, signature], () => _inner.checkEntry(signerPublicKey, entryBytes, signature));

  @override
  Future<bool> checkBundle(KeyBundle bundle, Uint8List signature) =>
      _once('bundle', [bundle.bytes, signature], () => _inner.checkBundle(bundle, signature));

  @override
  Future<bool> checkConfirmation(Uint8List statement, Uint8List signature, Uint8List confirmerPublicKey) => _once('confirmation', [
    statement,
    signature,
    confirmerPublicKey,
  ], () => _inner.checkConfirmation(statement, signature, confirmerPublicKey));

  @override
  Future<bool> checkRecoveryKey(Uint8List key) => _once('recovery key', [key], () => _inner.checkRecoveryKey(key));
}
