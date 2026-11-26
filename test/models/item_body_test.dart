@TestOn('vm')
library;

// The additions of Kemlock Server's item bodies (`crypto.md`, "Item bodies"): every member optional, left out when empty,
// and a body nobody edited written back as it was read.
import 'dart:convert';

import 'package:kemlock_core/features/duplicates/duplicate_rules.dart' show fileTagInput;
import 'package:kemlock_core/features/sync/kemlock/km_files.dart' show kmNamedFile;
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/item_link.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

const _a = '3f2c9a71-e4b0-4856-8a00-000000000001';
const _b = '3f2c9a71-e4b0-4856-8a00-000000000002';

final _fields = <Object?>[
  {'name': 'Employee ID', 'value': 'E-1', 'kind': 'text', 'adminField': '7d0f2c8e-0000-4000-8000-000000000001'},
  {'name': 'Active', 'value': 'true', 'kind': 'boolean'},
  {'name': 'Ref', 'value': 'x', 'kind': 'linked'},
];

final _links = <Object?>[
  {'id': _a},
  {'id': _b, 'note': 'x'},
];

/// A body the web vault wrote for each kind that takes custom fields, with `links` and `fields` added to it.
final _bodies = <String, ({Map<String, Object?> json, Map<String, Object?> Function(Map<String, Object?>) read})>{
  'login': (
    json: {
      'id': 'l1',
      'name': 'Mail',
      'username': 'ada',
      'password': 'pw',
      'websites': ['mail.example'],
      'addedAt': 1,
    },
    read: (json) => Login.fromJson(json).toJson(),
  ),
  'otp': (
    json: {
      'id': 'o1',
      'issuer': 'X',
      'label': 'me',
      'secret': 'JBSWY3DPEHPK3PXP',
      'algorithm': 'SHA1',
      'digits': 6,
      'period': 30,
      'addedAt': 1,
    },
    read: (json) => OtpAccount.fromJson(json).toJson(),
  ),
  'backup-codes': (
    json: {
      'id': 'b1',
      'serviceName': 'X',
      'codes': [
        {'code': '1111', 'used': false},
      ],
      'addedAt': 1,
    },
    read: (json) => BackupService.fromJson(json).toJson(),
  ),
  'note': (json: {'id': 'n1', 'title': 'T', 'text': 'x', 'addedAt': 1}, read: (json) => SecureNote.fromJson(json).toJson()),
  'card': (
    json: {'id': 'c1', 'name': 'Visa', 'number': '4111111111111111', 'addedAt': 1},
    read: (json) => PaymentCard.fromJson(json).toJson(),
  ),
  'identity': (json: {'id': 'i1', 'name': 'Me', 'email': 'me@example.org', 'addedAt': 1}, read: (json) => Identity.fromJson(json).toJson()),
  'contact': (
    json: {'id': 'k1', 'name': 'Ada', 'public': 'AAAA', 'source': 'file', 'addedAt': 1},
    read: (json) => Contact.fromJson(json).toJson(),
  ),
  'key': (
    json: {'id': 'p1', 'name': 'Key', 'kind': 'ssh', 'algorithm': 'ed25519', 'private': 'AAAA', 'origin': 'imported', 'addedAt': 1},
    read: (json) => VaultKey.fromJson(json).toJson(),
  ),
  'key-otp': (
    json: {
      'id': 'y1',
      'device': 'd',
      'name': 'X:me',
      'issuer': '',
      'label': 'me',
      'period': 30,
      'type': 'totp',
      'algorithm': 'SHA1',
      'addedAt': 1,
    },
    read: (json) => KeyAccount.fromJson(json).toJson(),
  ),
};

void main() {
  group('a body with links and custom fields', () {
    for (final MapEntry(:key, :value) in _bodies.entries) {
      test('$key writes back exactly what it read', () {
        final body = {...value.json, 'links': _links, 'fields': _fields, 'later': 1};
        expect(jsonEncode(value.read(body)), jsonEncode(body));
      });

      test('$key without them has neither member', () {
        expect(value.read(value.json).keys, isNot(anyOf(contains('links'), contains('fields'))));
        expect(jsonEncode(value.read(value.json)), jsonEncode(value.json));
      });
    }

    test('a passkey and a file take links and no custom fields', () {
      final passkey = Passkey.fromJson({
        'id': 'k',
        'credentialId': 'c',
        'rpId': 'x.example',
        'userHandle': 'u',
        'userName': 'ada',
        'privateKey': 'p',
        'addedAt': 1,
        'links': _links,
        'fields': _fields,
      });
      expect(passkey.links, hasLength(2));
      expect(passkey.extra, {'fields': _fields});
      expect(passkey.toJson()['fields'], _fields);
    });

    test('the members are typed and leave the unknown keys', () {
      final login = Login.fromJson({..._bodies['login']!.json, 'links': _links, 'fields': _fields, 'later': 1});
      expect(login.extra, {'later': 1});
      expect(login.links.map((link) => link.id), [_a, _b]);
      expect(login.fields.map((field) => field.name), ['Employee ID', 'Active', 'Ref']);
      expect(login.fields.first.adminField, '7d0f2c8e-0000-4000-8000-000000000001');
    });

    test('copyWith keeps them, stamping and moving to a space too', () {
      final login = Login.fromJson({..._bodies['login']!.json, 'links': _links, 'fields': _fields});
      for (final copy in [login.stamped(9), login.inSpace('fam'), login.copyWith(name: 'Other')]) {
        expect(copy.links, login.links);
        expect(copy.fields, login.fields);
      }
    });

    test('copyWith changes the fields, and an edited field writes only what changed', () {
      final login = Login.fromJson({..._bodies['login']!.json, 'fields': _fields});
      final edited = login.copyWith(
        fields: [
          login.fields.first.copyWith(value: 'E-2'),
          ...login.fields.skip(1),
        ],
      );
      final written = edited.toJson()['fields']! as List<Object?>;
      expect(written.first, {'name': 'Employee ID', 'value': 'E-2', 'kind': 'text', 'adminField': '7d0f2c8e-0000-4000-8000-000000000001'});
      expect(written.skip(1), _fields.skip(1));
    });

    test('empty lists leave the members out', () {
      final login = Login.fromJson({..._bodies['login']!.json, 'links': _links, 'fields': _fields});
      final bare = login.copyWith(links: const [], fields: const []);
      expect(bare.toJson(), _bodies['login']!.json);
    });

    test('a note keeps its attachments, links and fields together', () {
      const attachment = NoteAttachment(id: 'f', name: 'a.pdf', size: 3, key: 'k', addedAt: 2);
      final note = SecureNote.fromJson({
        'id': 'n',
        'title': 'T',
        'text': '',
        'addedAt': 1,
        'attachments': [attachment.toJson()],
        'links': _links,
        'fields': _fields,
      });
      expect(note.files.single, attachment);
      expect(note.links, hasLength(2));
      expect(note.fields, hasLength(3));
    });
  });

  group('login websites in step', () {
    final body = {
      'id': 'l1',
      'name': 'Mail',
      'websites': ['a.example', 'b.example'],
      'uris': [
        {'uri': 'a.example'},
        {'uri': 'https://b.example/x', 'match': 3},
        {'uri': '^https://.*\\.c\\.example', 'match': 4},
      ],
      'urls': ['a.example', 'https://b.example/x'],
      'addedAt': 1,
    };

    test('a body nobody edited keeps its urls as they are', () {
      final login = Login.fromJson(body);
      expect(login.stamped(2).toJson()['urls'], body['urls']);
      expect(login.copyWith(name: 'Mail 2').toJson()['urls'], body['urls']);
    });

    test('an edit of the websites writes urls again, without the regular expressions', () {
      final login = Login.fromJson(body);
      final edited = login.copyWith(uris: [...login.rules, const WebsiteRule('d.example')]);
      expect(edited.toJson()['urls'], ['a.example', 'https://b.example/x', 'd.example']);
    });

    test('a login that never had urls does not gain them', () {
      final login = Login.fromJson({
        'id': 'l1',
        'name': 'Mail',
        'websites': ['a.example'],
        'addedAt': 1,
      });
      expect(login.copyWith(websites: ['b.example']).toJson().containsKey('urls'), isFalse);
    });
  });

  group('an MFA code', () {
    test('has an optional name and websites', () {
      final account = OtpAccount.fromJson({
        'id': 'o1',
        'name': 'Work VPN',
        'issuer': 'X',
        'label': 'me',
        'secret': 'S',
        'websites': ['vpn.example'],
        'addedAt': 1,
      });
      expect(account.name, 'Work VPN');
      expect(account.websites, ['vpn.example']);
      expect(account.extra, isEmpty);
      expect(account.copyWith(name: unset).toJson().containsKey('name'), isFalse);
    });

    test('reads linkedLoginId, writes it back and never copies it into links', () {
      final body = {'id': 'o1', 'issuer': 'X', 'label': 'me', 'secret': 'S', 'algorithm': 'SHA1', 'digits': 6, 'period': 30, 'addedAt': 1};
      final account = OtpAccount.fromJson({...body, 'linkedLoginId': _a});
      expect(account.linkedLoginId, _a);
      expect(account.links, isEmpty);
      expect(account.extra, isEmpty);
      expect(account.toJson()['linkedLoginId'], _a);
      expect(account.copyWith(linkedLoginId: unset).toJson(), body);
    });
  });

  group('backup codes', () {
    test('have an optional name and websites', () {
      final service = BackupService.fromJson({
        'id': 'b1',
        'name': 'GitHub codes',
        'serviceName': 'GitHub',
        'codes': <Object?>[],
        'websites': ['github.com'],
        'addedAt': 1,
      });
      expect(service.name, 'GitHub codes');
      expect(service.websites, ['github.com']);
      expect(service.extra, isEmpty);
      expect(service.copyWith(websites: unset).toJson().containsKey('websites'), isFalse);
    });
  });

  group('a contact', () {
    test('may have no key: public is empty, left out, and the source is manual', () {
      const contact = Contact(
        id: 'k1',
        name: 'Ada',
        company: 'Analytical Engines',
        email: 'ada@example.org',
        phone: '+44 20 7946 0000',
        address: '12 Crown Row\nLondon',
        source: ContactSource.manual,
        addedAt: 1,
      );
      expect(contact.hasKey, isFalse);
      expect(contact.publicKey, '');
      final json = contact.toJson();
      expect(json.containsKey('public'), isFalse);
      expect(json['source'], 'manual');
      final read = Contact.fromJson(jsonDecode(jsonEncode(json)) as Map<String, Object?>);
      expect(read, contact);
      expect(
        (read.company, read.email, read.phone, read.address),
        ('Analytical Engines', 'ada@example.org', '+44 20 7946 0000', '12 Crown Row\nLondon'),
      );
    });

    test('a body written before them has none of the new members', () {
      final json = {'id': 'k1', 'name': 'Ada', 'public': 'AAAA', 'source': 'file', 'addedAt': 1};
      final contact = Contact.fromJson(json);
      expect(contact.hasKey, isTrue);
      expect(contact.toJson(), json);
    });
  });

  group('an attachment', () {
    const digest = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    final json = {'id': 'f', 'name': 'a.pdf', 'size': 3, 'key': 'k', 'addedAt': 2, 'sha256': digest, 'kemlockFile': 'srv-1'};

    test('reads its sha256 out of the unknown keys', () {
      final attachment = NoteAttachment.fromJson(json);
      expect(attachment.sha256, digest);
      expect(attachment.extra, {'kemlockFile': 'srv-1'});
      expect(attachment.toJson(), json);
    });

    test('keeps a sha256 that is not 64 hex digits as it was', () {
      for (final bad in <Object?>['E3B0C442', 5, 'sha256:' + digest]) {
        final attachment = NoteAttachment.fromJson({...json, 'sha256': bad});
        expect(attachment.sha256, isNull);
        expect(attachment.toJson()['sha256'], bad);
      }
    });

    test('reads a sha256 in upper case or with spaces around it, and writes it back as it was', () {
      for (final written in [digest.toUpperCase(), ' $digest ', ' ' + digest.toUpperCase() + '
']) {
        final body = {...json, 'sha256': written};
        final item = VaultFile.fromJson({'id': 'f1', 'name': 'a.pdf', 'file': body, 'addedAt': 1});

        expect(item.file.sha256, digest);
        expect(item.file.toJson()['sha256'], written);
        expect(item.toJson()['file'], body, reason: 'an item nobody edited stays as it was');
        expect(fileTagInput(item)!.values, [digest]);
      }
    });

    test('a new hash replaces the member the body held under that name', () {
      for (final held in <Object?>[digest.toUpperCase(), 'junk', 7]) {
        final other = 'a' * 64;
        final attachment = NoteAttachment.fromJson({...json, 'sha256': held});

        expect(attachment.withSha256(other).toJson()['sha256'], other);
        expect(kmNamedFile(attachment, 'srv-2', sha256: other).toJson()['sha256'], other);
      }
      // Naming a file with the hash it holds leaves the member as written
      final upper = NoteAttachment.fromJson({...json, 'sha256': digest.toUpperCase()});
      expect(kmNamedFile(upper, 'srv-2', sha256: digest).toJson()['sha256'], digest.toUpperCase());
    });

    test('an attachment without one writes none', () {
      final attachment = NoteAttachment.fromJson({'id': 'f', 'name': 'a', 'size': 1, 'key': 'k', 'addedAt': 2});
      expect(attachment.sha256, isNull);
      expect(attachment.toJson().containsKey('sha256'), isFalse);
      expect(attachment.withSha256(digest).sha256, digest);
    });
  });

  group('the attachments of a note', () {
    Map<String, Object?> file(String id) => {'id': id, 'name': '$id.pdf', 'size': 1, 'key': 'k', 'addedAt': 1, 'kemlockFile': 'srv-$id'};

    test('keeps an entry that is not an object where it was, whatever is done to the files', () {
      final body = {
        'id': 'n1',
        'title': 'Papers',
        'text': '',
        'addedAt': 1,
        'attachments': [file('a'), 'an entry of a later version', file('b'), 5, null],
      };
      final note = SecureNote.fromJson(body);

      expect(note.files.map((attachment) => attachment.id), ['a', 'b'], reason: 'only the readable ones are files');
      expect(note.unreadAttachments, hasLength(3));
      expect(note.toJson(), body);

      final fewer = note.copyWith(attachments: [note.files.last]);
      expect(fewer.toJson()['attachments'], [file('b'), 'an entry of a later version', 5, null]);
      final more = note.copyWith(attachments: [...note.files, NoteAttachment.fromJson(file('c'))]);
      expect(more.toJson()['attachments'], [file('a'), 'an entry of a later version', file('b'), 5, file('c'), null]);
      expect(note.copyWith(title: 'Other').toJson()['attachments'], body['attachments']);
    });

    test('of a body that holds only entries this version cannot read are written back', () {
      final body = {'id': 'n1', 'title': 'T', 'text': '', 'addedAt': 1, 'attachments': ['x']};
      final note = SecureNote.fromJson(body);

      expect(note.files, isEmpty);
      expect(note.toJson(), body);
    });
  });

  group('a File item', () {
    final body = {
      'id': _a,
      'name': 'passport.pdf',
      'notes': 'scan',
      'favorite': true,
      'file': {'id': 'f', 'name': 'passport.pdf', 'size': 3, 'type': 'application/pdf', 'key': 'k', 'addedAt': 2, 'kemlockFile': 'srv-1'},
      'links': _links,
      'addedAt': 5,
      'updatedAt': 6,
      'later': 1,
    };

    test('writes back what it read', () {
      final file = VaultFile.fromJson(body);
      expect(file.name, 'passport.pdf');
      expect(file.file.extra, {'kemlockFile': 'srv-1'});
      expect(file.links, hasLength(2));
      expect(file.extra, {'later': 1});
      expect(file.changedAt, 6);
      expect(jsonEncode(file.toJson()), jsonEncode(body));
    });

    test('reads a body with no addedAt as 0', () {
      final file = VaultFile.fromJson({'id': _a, 'name': 'x', 'file': body['file']});
      expect(file.addedAt, 0);
    });

    test('stamps, moves to a space and links like the other entries', () {
      final file = VaultFile.fromJson(body);
      expect(file.stamped(9).updatedAt, 9);
      expect(file.inSpace('fam').spaceId, 'fam');
      expect(file.inSpace('').spaceId, isNull);
      expect(file.withLinks([const ItemLink(_b)]).toJson()['links'], [
        {'id': _b},
      ]);
      expect(file.copyWith(notes: unset, favorite: unset).toJson().keys, isNot(anyOf(contains('notes'), contains('favorite'))));
    });
  });
}
