@TestOn('vm')
library;

// A PGP key on a security key's OpenPGP card (openspec: add-openpgp-card)
// travels as any key does: through a WebDAV sync file and its merge, and
// through Vaultwarden, whose note for it hides an armored stub that holds
// no secret.
import 'dart:io';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/keys.dart' as keys;
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart' show cardStubSerials;
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_items.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

final _stub = File('test/fixtures/keys/gnupg/card/stub-ed25519.gpg').readAsBytesSync();

final _cardKey = VaultKey.fromJson({
  'id': '0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f',
  'name': 'On the card',
  'kind': 'pgp',
  'algorithm': 'pgp',
  'private': b64(_stub),
  'public': b64(File('test/fixtures/keys/gnupg/ed25519.public.gpg').readAsBytesSync()),
  'origin': 'imported',
  'protected': true,
  'addedAt': 1794038400000,
  'card': {
    'aid': 'D276000124010304FFFF123456780000',
    'slots': {'sig': '1FCDA135EE42400EC2B77CE677249ABE661CF8DB', 'dec': '4BA83174FC8CE762A23BF0A4841A40E3B199EA67'},
  },
});

void main() {
  group('WebDAV', () {
    test('a sync file carries the card key, card and stub as they were', () async {
      final key = randomBytes(32);

      final doc = await decryptSyncFile(await encryptSyncFile(SyncDoc(keys: [_cardKey]), key), key);

      expect(doc.keys.single.toJson(), _cardKey.toJson());
      expect(doc.keys.single.isOnCard, isTrue);
    });

    test('a device without the key takes it from the merge with its card', () {
      final merged = mergeScope(const Lists(), const [], SyncDoc(keys: [_cardKey]), now: 1794038400000 + 1000);

      expect(merged.doc.keys.single.toJson(), _cardKey.toJson());
    });

    group('a key moved to the card on one device (task 11.4)', () {
      final full = VaultKey.fromJson({
        ...(_cardKey.toJson()..remove('card')),
        'private': b64(File('test/fixtures/keys/gnupg/ed25519.secret.gpg').readAsBytesSync()),
        'protected': null,
        'updatedAt': 1794038400000 + 1000,
      });
      final moved = full.movedToCard(stub: b64(_stub), card: _cardKey.card!, at: 1794038400000 + 5000);

      test('a second device holding the full key ends with the card key', () {
        final merged = mergeScope(
          Lists(keys: [full]),
          const [],
          SyncDoc(keys: [moved]),
          now: 1794038400000 + 9000,
        );

        final key = merged.doc.keys.single;
        expect(key.toJson(), moved.toJson());
        expect(key.isOnCard, isTrue);
        expect(cardStubSerials(unb64(key.privateKey)), isNotEmpty);
      });

      test('the device that moved it keeps the card key against the older full one', () {
        final merged = mergeScope(
          Lists(keys: [moved]),
          const [],
          SyncDoc(keys: [full]),
          now: 1794038400000 + 9000,
        );

        expect(merged.doc.keys.single.toJson(), moved.toJson());
      });

      // Joined with add-pgp-key-editing, whose combineKeyCopies runs before mergeScope
      group('combined first, as the sync code runs it', () {
        Future<VaultKey> sync(VaultKey local, VaultKey remote) async {
          final doc = SyncDoc(keys: [remote]);
          final merged = mergeScope(await combineKeyCopies(Lists(keys: [local]), doc), [local.id], doc, now: 1794038400000 + 9000);
          return merged.doc.keys.single;
        }

        void expectOnCard(VaultKey key) {
          expect(key.card, _cardKey.card);
          expect(key.isOnCard, isTrue);
          final private = unb64(key.privateKey);
          expect(keys.readPgpKeyInfo(private).protected, isTrue);
          expect(cardStubSerials(private), hasLength(2), reason: 'both keys still divert to the card: no secret came back');
        }

        test('the newer moved entry keeps its stub against the full copy, on either phone', () async {
          final onTheOther = await sync(full, moved);
          final onTheMover = await sync(moved, full);

          expect(onTheOther.toJson(), moved.toJson());
          expect(onTheMover.toJson(), moved.toJson());
          expectOnCard(onTheOther);
        });

        test('a full copy that holds more, but is older, adds its user ID and leaves the stub and the card', () async {
          final made = await keys.makeKey(
            keys.PgpChangeRequest(
              unb64(full.privateKey),
              const keys.AddPgpUserId(name: 'Ada', email: 'ada@work.example'),
              now: DateTime.utc(2026, 11, 20, 12),
            ),
          );
          final grown = full
              .withHalves(privateKey: b64(made.private), publicKey: b64(made.public!), protected: false)
              .copyWith(updatedAt: 1794038400000 + 3000);

          for (final (local, remote) in [(grown, moved), (moved, grown)]) {
            final key = await sync(local, remote);

            expectOnCard(key);
            expect(keys.readPgpKeyInfo(unb64(key.publicKey!)).userIds, hasLength(2));
            expect(keys.readPgpKeyInfo(unb64(key.privateKey)).userIds, hasLength(2));
            expect(key.updatedAt, moved.updatedAt! + 1, reason: 'a millisecond after the moved entry');
            expect((key.id, key.name, key.addedAt), (moved.id, moved.name, moved.addedAt));
          }
        });
      });
    });
  });

  group('Vaultwarden', () {
    const home = 'wJ2kX9c4Qm1zR7tB';

    test('the sealed entry and the plain field keep the card', () async {
      final key = randomBytes(32);

      final opened = await openSealedEntry(await sealEntry(_cardKey, home, key), key);
      final read = PlainField.tryParse(PlainField(home: home, own: true, sum: 'c3Vt', entry: _cardKey).toText())!;

      expect((opened as VaultKey).toJson(), _cardKey.toJson());
      expect((read.entry as VaultKey).toJson(), _cardKey.toJson());
    });

    test("the note's hidden field holds the armored stub, which holds no secret", () async {
      final text = await privateKeyText(_cardKey);

      expect(text, contains('BEGIN PGP PRIVATE KEY BLOCK'));
      final bytes = readArmor(readPemBlocks(text).single);
      expect(bytes, _stub);
      final info = keys.readPgpKeyInfo(bytes);
      expect(info.protected, isTrue);
      expect(cardStubSerials(bytes), hasLength(2), reason: 'both keys divert to the card');
      // The note's text is the public key, as for any PGP key
      expect(keyNoteText(_cardKey), contains('BEGIN PGP PUBLIC KEY BLOCK'));
    });
  });
}
