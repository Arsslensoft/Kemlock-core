@TestOn('vm')
library;

// Identity documents, contacts and certificates in the duplicate finder (crypto.md, "Duplicate tags").
import 'package:kemlock_core/features/duplicates/dedup_cache.dart';
import 'package:kemlock_core/features/duplicates/dedup_store.dart';
import 'package:kemlock_core/features/duplicates/dedup_tagger.dart';
import 'package:kemlock_core/features/duplicates/duplicate_matcher.dart';
import 'package:kemlock_core/features/duplicates/duplicate_rules.dart';
import 'package:kemlock_core/features/duplicates/duplicate_tags.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

Identity _identity(String id, {String name = 'Zoe Muller', String email = 'zoe@example.org', List<String> documents = const []}) => Identity(
  id: id,
  name: 'Identity $id',
  givenName: name,
  email: email,
  documents: [
    for (final (index, number) in documents.indexed) IdentityDocument(id: '$id-$index', number: number),
  ],
  addedAt: 1,
);

Contact _contact(String id, {String? email, String? phone, String publicKey = ''}) => Contact(
  id: id,
  name: 'Contact $id',
  email: email,
  phone: phone,
  publicKey: publicKey,
  source: publicKey.isEmpty ? ContactSource.manual : ContactSource.file,
  addedAt: 1,
);

List<String> _groups(List<Object> entries, {KeyIdentityOf? keyIdentityOf}) {
  final items = dedupItems(identities: entries.whereType<Identity>().toList(), contacts: entries.whereType<Contact>().toList());
  final cache = DedupCache.fresh('list');
  final result = refreshTags(cache, items, dedupOwners(cache, const []), keyIdentityOf: keyIdentityOf);
  final tags = {for (final MapEntry(:key, :value) in result.cache.owners.entries) key: value.items};
  final groups = findDuplicates(items: items, tags: tags, keyIdentityOf: keyIdentityOf);
  return [
    for (final group in groups) '${group.reason.name}: ${(group.items.map((item) => item.id).toList()..sort()).join(',')}',
  ];
}

void main() {
  group('the tags of an identity', () {
    test('are one identity tag and one document tag for each document number, each once', () {
      final inputs = tagInputsOf(_identity('a', documents: ['X 1234-567', 'x1234567', 'P 99 88']));
      expect([for (final input in inputs) input.array], [
        ['identity', 'zoe muller', 'zoe@example.org'],
        ['document', 'x1234567'],
        ['document', 'p9988'],
      ]);
    });

    test('leave out a document number of fewer than four letters and digits', () {
      expect(tagInputsOf(_identity('a', documents: ['1-2-3'])).where((input) => input.kind == TagKind.document), isEmpty);
    });
  });

  group('identities are copies', () {
    test('when they share a document number, whatever their names', () {
      final groups = _groups([
        _identity('a', name: 'Zoe', email: 'one@example.org', documents: ['X 1234-567']),
        _identity('b', name: 'Zoe M', email: 'two@example.org', documents: ['x1234567', 'Z 55 66 77']),
      ]);
      expect(groups, ['sameDocument: a,b']);
    });

    test('with no document when they share a name and email', () {
      expect(_groups([_identity('a'), _identity('b'), _identity('c', name: 'Other')]), ['sameIdentity: a,b']);
    });

    test('with no document and the one identity with documents that shares them', () {
      expect(_groups([_identity('a'), _identity('b', documents: ['X 1234-567'])]), ['sameIdentity: a,b']);
      expect(
        _groups([_identity('a'), _identity('b'), _identity('c', documents: ['X 1234-567'])]),
        ['sameIdentity: a,b,c'],
      );
    });

    test('of none of several that have documents, nor are two that have documents', () {
      expect(_groups([_identity('a'), _identity('b', documents: ['X 1234-567']), _identity('c', documents: ['Y 7654-321'])]), isEmpty);
      expect(_groups([_identity('a', documents: ['X 1234-567']), _identity('b', documents: ['Y 7654-321'])]), isEmpty);
    });

    test('but two without documents are still copies when others with documents share their name', () {
      expect(
        _groups([_identity('a'), _identity('b'), _identity('c', documents: ['X 1234-567']), _identity('d', documents: ['Y 7654-321'])]),
        ['sameIdentity: a,b'],
      );
    });
  });

  group('contacts', () {
    test('make a tag of the email and the phone', () {
      expect([for (final input in tagInputsOf(_contact('a', email: ' Alex.Chen@Example.ORG ', phone: '+1 (555) 0142'))) input.array], [
        ['contact', 'alex.chen@example.org', '15550142'],
      ]);
      expect(tagInputsOf(_contact('b', email: ' ', phone: 'call me')), isEmpty);
    });

    test('are copies when they share an email and a phone, and not otherwise', () {
      expect(
        _groups([
          _contact('a', email: 'a@example.org', phone: '1-555-0142'),
          _contact('b', email: 'A@example.org', phone: '+1 555 0142'),
          _contact('c', email: 'a@example.org'),
        ]),
        ['sameContact: a,b'],
      );
    });

    test('with a key make a key tag too, and one without a key makes none', () {
      final keyed = _contact('a', email: 'a@example.org', publicKey: 'AAAA');
      expect([for (final input in tagInputsOf(keyed, keyIdentityOf: (_) => 'ABCDEF')) input.kind], [TagKind.contact, TagKind.key]);
      final keyless = _contact('b', email: 'a@example.org');
      expect([for (final input in tagInputsOf(keyless, keyIdentityOf: dedupKeyIdentity)) input.kind], [TagKind.contact]);
    });
  });

  group('a certificate', () {
    // A certificate's PEM: its SHA-256 is that of the DER, which is these bytes
    const pem = '-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n';
    const thumbprint = '9F64A747E1B97F131FABB6B447296C9B6F0201E79FB3C5356E6C77E89B6A806A';

    VaultKey certificate(Map<String, Object?> extra) => VaultKey(
      id: 'c',
      name: 'Certificate',
      kind: 'signing',
      algorithm: 'ed25519',
      privateKey: 'p',
      publicKey: 'AAAA',
      origin: KeyOrigin.imported,
      addedAt: 1,
      extra: {'certificate': pem, ...extra},
    );

    test('is told by the SHA-256 of its DER, as upper-case hexadecimal', () {
      expect(dedupKeyIdentity(certificate(const {})), thumbprint);
    });

    test('is told by the fingerprint its body stores, as normalised', () {
      expect(dedupKeyIdentity(certificate({'fingerprint': 'ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01'})), 'ABCDEF0123456789ABCDEF0123456789ABCDEF01');
    });

    test('makes no tag when the certificate cannot be read', () {
      final broken = VaultKey(
        id: 'c',
        name: 'Certificate',
        kind: 'signing',
        algorithm: 'ed25519',
        privateKey: 'p',
        origin: KeyOrigin.imported,
        addedAt: 1,
        extra: const {'certificate': 'not a certificate'},
      );
      expect(dedupKeyIdentity(broken), isNull);
    });
  });
}
