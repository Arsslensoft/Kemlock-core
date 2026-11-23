@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/spaces/chain_json.dart';
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

Matcher refusedAs(ChainProblem problem) => throwsA(isA<ChainRefusal>().having((e) => e.problem, 'problem', problem));

Uint8List hexBytes(String hex) =>
    Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);

// The record of a space's chain: its JCS bytes, its link and its signature under "space-chain". The expected
// bytes are written out by hand from the space chain section of docs/crypto.md, version 2.
void main() {
  final zeros = 'A' * 43; // 32 zero bytes as base64url without padding
  final fenceBody = '{"home":"${uuid(0xf2)}","promotion":"${b64urlEncode(Uint8List(32))}"}';

  /// The text of a record of [kind] at `seq` 0 with [body] as it is written.
  String record(String body, {String kind = 'fence'}) =>
      '{"at":5,"body":$body,"by":"${uuid(2)}","epoch":1,"kind":"$kind","prev":"$zeros","seq":0,"space":"${uuid(1)}","v":1}';

  SpaceChainEntry entry({Map<String, Object?>? body, int seq = 0, int epoch = 1, ChainKind kind = ChainKind.fence}) => SpaceChainEntry(
    space: uuid(1),
    seq: seq,
    prev: Uint8List(32),
    epoch: epoch,
    at: 5,
    by: uuid(2),
    kind: kind,
    body: body ?? {'home': uuid(0xf2), 'promotion': b64urlEncode(Uint8List(32))},
  );

  test('is the RFC 8785 text of its members, sorted, with the link as base64url', () {
    expect(
      utf8.decode(entry(body: {'z': 1, 'a': 'x'}).bytes),
      '{"at":5,"body":{"a":"x","z":1},"by":"${uuid(2)}","epoch":1,"kind":"fence","prev":"$zeros","seq":0,"space":"${uuid(1)}","v":1}',
    );
    expect(utf8.decode(entry().bytes), record(fenceBody));
  });

  // PROVISIONAL: the spec's two link examples were computed by hand (openssl over the label and the bytes). They
  // stand in for test-vectors/space-chain.json until the server's vectors arrive, and are replaced by them.
  group('the spec examples (provisional)', () {
    const fenceText =
        '{"at":1700000700,"body":{"home":"00000000-0000-4000-8000-0000000000f2","promotion":"QTHxrde9FN788OzrLL4TpaPmaC2O0E5WgPn8_Ws-K0Q"},'
        '"by":"00000000-0000-4000-8000-000000000002","epoch":2,"kind":"fence","prev":"ERERERERERERERERERERERERERERERERERERERERERE","seq":7,'
        '"space":"00000000-0000-4000-8000-000000000001","v":1}';
    const roleText =
        '{"at":1700000800,"body":{"custom":["create-collections","manage-users"],"member":"00000000-0000-4000-8000-000000000003","role":"custom"},'
        '"by":"00000000-0000-4000-8000-000000000002","epoch":2,"kind":"role","prev":"uvX9tlngJ-iM_l8qaPBeH7JTetnJnqKzeGn_WSRTaUc","seq":8,'
        '"space":"00000000-0000-4000-8000-000000000001","v":1}';

    test('a fence at seq 7 is 313 bytes and linked by SHA-256 of the label and its bytes', () {
      final bytes = utf8.encode(fenceText);
      expect(bytes, hasLength(313));
      final read = SpaceChainEntry.parse(bytes);
      expect(read.bytes, bytes);
      expect(read.prev, everyElement(0x11));
      expect(read.body['promotion'], b64urlEncode(hash.sha256.convert(utf8.encode('example promotion record')).bytes));
      expect(read.hashed, hexBytes('baf5fdb659e027e88cfe5f2a68f05e1fb2537ad9c99ea2b37869ff5924536947'));
      expect(b64urlEncode(read.hashed), 'uvX9tlngJ-iM_l8qaPBeH7JTetnJnqKzeGn_WSRTaUc');
      // A verifier that hashes without the label gets 04cce6ca...7016608a
      final unlabelled = hash.sha256.convert(bytes).bytes;
      expect(unlabelled.sublist(0, 4), [0x04, 0xcc, 0xe6, 0xca]);
      expect(unlabelled.sublist(28), [0x70, 0x16, 0x60, 0x8a]);
      expect(read.hashed, isNot(unlabelled));
    });

    test('a role at seq 8 is 319 bytes and holds the link of the fence', () {
      final bytes = utf8.encode(roleText);
      expect(bytes, hasLength(319));
      final fence = SpaceChainEntry.parse(utf8.encode(fenceText));
      final read = SpaceChainEntry.parse(bytes);
      expect(read.bytes, bytes);
      expect(read.prev, fence.hashed);
      expect(read.hashed, hexBytes('8aa6fb9d20088eeb1cbb86b48f0ded3b0aa2120cc7ebdbbc5f288e7b637336af'));
      expect(b64urlEncode(read.hashed), 'iqb7nSAIjuscu4a0jw3tOwqiEgzH69u8XyiOe2NzNq8');
    });
  });

  test('links the first record to 32 zero bytes', () {
    expect(chainGenesisLink, everyElement(0));
    expect(chainGenesisLink, hasLength(32));
    expect(b64urlEncode(chainGenesisLink), zeros);
    final first = entry();
    expect(first.hashed, hasLength(32));
    expect(first.hashed, isNot(hash.sha256.convert(first.bytes).bytes));
  });

  test('reads its own bytes back, and nothing but them', () {
    final original = entry(seq: 4);
    final read = SpaceChainEntry.parse(original.bytes);
    expect(read.bytes, original.bytes);
    expect(read.kind, ChainKind.fence);
    expect(read.seq, 4);
    expect(read.body, {'home': uuid(0xf2), 'promotion': b64urlEncode(Uint8List(32))});
    expect(() => SpaceChainEntry.parse(utf8.encode('not json')), throwsA(isA<MalformedException>()));
    expect(() => SpaceChainEntry.parse([0xff, 0xfe]), throwsA(isA<MalformedException>()));
  });

  group('refuses as malformed', () {
    final text = record(fenceBody);

    void refuses(String name, String Function(String) change) {
      test(name, () {
        expect(() => SpaceChainEntry.parse(utf8.encode(change(text))), throwsA(isA<MalformedException>()));
      });
    }

    refuses('a space after a colon', (t) => t.replaceFirst('"at":5', '"at": 5'));
    refuses('a space before the first member', (t) => t.replaceFirst('{"at"', '{ "at"'));
    refuses('a newline at the end', (t) => '$t\n');
    refuses('anything after the closing brace', (t) => '$t{}');
    refuses('a different order of members', (t) => t.replaceFirst('"epoch":1,"kind":"fence"', '"kind":"fence","epoch":1'));
    refuses('a member name twice', (t) => t.replaceFirst('"at":5,', '"at":5,"at":5,'));
    refuses('a member name twice in the body', (t) => t.replaceFirst('{"home"', '{"home":"${uuid(1)}","home"'));
    refuses('an unknown member', (t) => t.replaceFirst('"v":1', '"w":1,"v":1'));
    refuses('an unknown member of the body', (t) => t.replaceFirst('{"home"', '{"extra":1,"home"'));
    refuses('null for a value', (t) => t.replaceFirst('"seq":0', '"seq":null'));
    refuses('null for a member of the body', (t) => t.replaceFirst('"home":"${uuid(0xf2)}"', '"home":null'));
    refuses('1.0', (t) => t.replaceFirst('"seq":0', '"seq":1.0'));
    refuses('1e0', (t) => t.replaceFirst('"seq":0', '"seq":1e0'));
    refuses('1E0', (t) => t.replaceFirst('"seq":0', '"seq":1E0'));
    refuses('-1', (t) => t.replaceFirst('"seq":0', '"seq":-1'));
    refuses('-0', (t) => t.replaceFirst('"seq":0', '"seq":-0'));
    refuses('a leading zero', (t) => t.replaceFirst('"at":5', '"at":05'));
    refuses('2^53', (t) => t.replaceFirst('"at":5', '"at":9007199254740992'));
    refuses('a number of 40 digits', (t) => t.replaceFirst('"at":5', '"at":${'9' * 40}'));
    refuses('a string with an escape', (t) => t.replaceFirst('"kind":"fence"', r'"kind":"fen\ce"'));
    refuses('a lone surrogate', (t) => t.replaceFirst('"kind":"fence"', r'"kind":"\ud800"'));
    refuses('a backslash anywhere in a string', (t) => t.replaceFirst('"kind":"fence"', r'"kind":"fen\\ce"'));
    refuses('a space in a string', (t) => t.replaceFirst('"kind":"fence"', '"kind":"fen ce"'));
    refuses('a dot in a string', (t) => t.replaceFirst('"kind":"fence"', '"kind":"fen.ce"'));
    refuses('a member name that is not letters', (t) => t.replaceFirst('"v":1', '"v1":1'));
    refuses('a single quote', (t) => t.replaceAll('"', "'"));
    refuses('a byte-order mark', (t) => '\u{feff}$t');
    refuses('a text of non-ASCII letters', (t) => t.replaceFirst('"kind":"fence"', '"kind":"fénce"'));
    refuses('a body that is not its kind\'s', (_) => record('{}'));
    refuses('a body of another kind', (_) => record(fenceBody, kind: 'group'));
  });

  group('the strict reader', () {
    test('reads objects nested 6 deep and refuses 7', () {
      expect(readChainJson(utf8.encode('{"a":{"a":{"a":{"a":{"a":{"x":1}}}}}}')), isA<Map<String, Object?>>());
      expect(() => readChainJson(utf8.encode('{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}')), throwsA(isA<MalformedException>()));
    });

    test('reads integers up to 2^53 - 1, true and false', () {
      expect(readChainJson(utf8.encode('{"a":9007199254740991,"b":true,"c":false,"d":[0,1]}')), {
        'a': 9007199254740991,
        'b': true,
        'c': false,
        'd': [0, 1],
      });
    });
  });

  group('refuses an entry that is', () {
    Map<String, Object?> json() => {...entry().toJson()};

    for (final (name, change) in <(String, void Function(Map<String, Object?>))>[
      ('of another version', (j) => j['v'] = 2),
      ('missing a member', (j) => j.remove('by')),
      ('carrying an unknown member', (j) => j['extra'] = 1),
      ('of an unknown kind', (j) => j['kind'] = 'promote'),
      ('with a fractional sequence number', (j) => j['seq'] = 1.5),
      ('with a negative sequence number', (j) => j['seq'] = -1),
      ('with a sequence number past 65,535', (j) => j['seq'] = 65536),
      ('of epoch 0', (j) => j['epoch'] = 0),
      ('of an epoch past 2^32 - 1', (j) => j['epoch'] = 0x100000000),
      ('with a signer that is not a UUID', (j) => j['by'] = 'alice'),
      ('with an upper-case space UUID', (j) => j['space'] = uuid(0xab).toUpperCase()),
      ('with a padded link', (j) => j['prev'] = '$zeros='),
      ('with a link of 31 bytes', (j) => j['prev'] = 'A' * 42),
      ('with a body that is not an object', (j) => j['body'] = []),
    ]) {
      test(name, () {
        final changed = json();
        change(changed);
        expect(() => SpaceChainEntry.fromJson(changed), throwsA(isA<MalformedException>()));
      });
    }
  });

  group('limits', () {
    test('a record of 196,609 bytes is too large, and one of 196,608 is only read', () {
      expect(() => SpaceChainEntry.parse(Uint8List(196609)), refusedAs(ChainProblem.tooLarge));
      expect(() => SpaceChainEntry.parse(Uint8List(196608)), throwsA(isA<MalformedException>()));
    });

    test('a chain of 65,537 records is too large, whatever they are', () {
      expect(() => parseChain(List<Object?>.filled(65537, const <String, Object?>{})), refusedAs(ChainProblem.tooLarge));
    });

    test('a chain is an array, and one bad element refuses all of it', () {
      expect(() => parseChain({'entry': 'x'}), refusedAs(ChainProblem.malformed));
      final good = SignedChainEntry(entry(), Uint8List(Sig1.signatureLength)).toJson();
      expect(parseChain([good]), hasLength(1));
      expect(() => parseChain([good, <String, Object?>{}]), refusedAs(ChainProblem.malformed));
      final spaced = {...good, 'entry': b64urlEncode(utf8.encode(utf8.decode(entry().bytes).replaceFirst('"at":5', '"at": 5')))};
      expect(() => parseChain([good, spaced]), refusedAs(ChainProblem.malformed));
    });

    test('the refusal of an element names its position, which is its seq in a chain read from seq 0', () {
      final good = SignedChainEntry(entry(), Uint8List(Sig1.signatureLength)).toJson();
      Matcher at(int index) => throwsA(isA<ChainRefusal>().having((e) => e.index, 'index', index));
      expect(() => parseChain([good, <String, Object?>{}]), at(1));
      expect(() => parseChain([<String, Object?>{}, good]), at(0));
      // A chain refused as a whole has no position
      expect(() => parseChain({'entry': 'x'}), throwsA(isA<ChainRefusal>().having((e) => e.index, 'index', isNull)));
    });
  });

  group('the wire form', () {
    final rekeyBody = {'bundle': b64urlEncode(Uint8List(3621)), 'bundleSignature': b64urlEncode(Uint8List(Sig1.signatureLength))};

    test('a signed entry travels as its exact bytes and its signature, and reads back', () {
      final signed = SignedChainEntry(entry(), Uint8List(Sig1.signatureLength));
      final json = signed.toJson();
      expect(json.keys, {'entry', 'signature'});
      final read = SignedChainEntry.fromJson(json);
      expect(read.entry.bytes, signed.entry.bytes);
      expect(read.signature, signed.signature);
      expect(read.cosignature, isNull);
      expect(() => SignedChainEntry(entry(), Uint8List(10)), throwsA(isA<MalformedException>()));
      expect(
        () => SignedChainEntry.fromJson({'entry': json['entry'], 'signature': json['signature'], 'by': 'x'}),
        throwsA(isA<MalformedException>()),
      );
      expect(() => SignedChainEntry.fromJson({'entry': json['entry']}), throwsA(isA<MalformedException>()));
    });

    test('a rekey carries a cosignature of 3,373 bytes as a third member', () {
      final signed = SignedChainEntry(
        entry(kind: ChainKind.rekey, body: rekeyBody),
        Uint8List(Sig1.signatureLength),
        cosignature: Uint8List(Sig1.signatureLength)..[0] = 9,
      );
      final json = signed.toJson();
      expect(json.keys, {'cosignature', 'entry', 'signature'});
      final read = SignedChainEntry.fromJson(json);
      expect(read.cosignature, signed.cosignature);
      expect(
        () => SignedChainEntry(entry(), Uint8List(Sig1.signatureLength), cosignature: Uint8List(10)),
        throwsA(isA<MalformedException>()),
      );
      expect(() => SignedChainEntry.fromJson({...json, 'cosignature': 5}), throwsA(isA<MalformedException>()));
    });

    test('a rekey without a cosignature is malformed', () {
      final bare = SignedChainEntry(entry(kind: ChainKind.rekey, body: rekeyBody), Uint8List(Sig1.signatureLength)).toJson();
      expect(() => SignedChainEntry.fromJson(bare), throwsA(isA<MalformedException>()));
    });

    test('a cosignature on any other kind is malformed', () {
      final grant = {'collection': uuid(5), 'grantee': 'user:${uuid(3)}', 'permission': 'view'};
      final json = SignedChainEntry(
        entry(kind: ChainKind.grant, body: grant),
        Uint8List(Sig1.signatureLength),
        cosignature: Uint8List(Sig1.signatureLength),
      ).toJson();
      expect(() => SignedChainEntry.fromJson(json), throwsA(isA<MalformedException>()));
    });
  });

  group('with real sig1 keys', () {
    late Uint8List privateKey;
    late Uint8List publicKey;
    late Uint8List otherPrivate;

    setUpAll(() async {
      final pair = await Sig1.generate(Uint8List.fromList(List.generate(64, (i) => i + 1)));
      privateKey = pair.privateKey;
      publicKey = pair.publicKey;
      otherPrivate = (await Sig1.generate(Uint8List.fromList(List.generate(64, (i) => i + 70)))).privateKey;
    });

    test('is signed and verified under the context "space-chain"', () async {
      expect(SignContext.spaceChain, 'space-chain');
      final signed = await signChainEntry(entry(), privateKey);
      expect(signed.signature, hasLength(Sig1.signatureLength));
      expect(await verifyChainEntry(signed, publicKey), isTrue);
      expect(await const RealChainCrypto().checkEntry(publicKey, signed.entry.bytes, signed.signature), isTrue);
    });

    test('does not verify for another entry, another key or a changed signature', () async {
      final signed = await signChainEntry(entry(), privateKey);
      final other = SignedChainEntry(entry(seq: 1), signed.signature);
      expect(await verifyChainEntry(other, publicKey), isFalse);
      final byAnother = await signChainEntry(entry(), otherPrivate);
      expect(await verifyChainEntry(byAnother, publicKey), isFalse);
      final changed = SignedChainEntry(signed.entry, Uint8List.fromList(signed.signature)..[100] ^= 1);
      expect(await verifyChainEntry(changed, publicKey), isFalse);
    });

    test('a signature made under the context "manifest" or "bundle" is refused as an entry', () async {
      final bytes = entry().bytes;
      for (final context in [SignContext.manifest, SignContext.bundle, SignContext.confirm]) {
        final made = await Sig1.sign(privateKey, bytes, context: context);
        expect(await verifyChainEntry(SignedChainEntry(entry(), made), publicKey), isFalse, reason: context);
        // It is a good signature in its own context
        expect(await Sig1.verify(publicKey, bytes, made, context: context), isTrue, reason: context);
      }
    });

    test('the signed message starts with the label, the context and the length of the record', () {
      expect(hex(utf8.encode('kemlock/v1/sig1')), '6b656d6c6f636b2f76312f73696731');
      expect(hex(u32be(11)), '0000000b');
      expect(hex(utf8.encode(SignContext.spaceChain)), '73706163652d636861696e');
    });
  });
}

String hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();
