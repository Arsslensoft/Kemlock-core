@TestOn('vm')
library;

import 'package:kemlock_core/features/duplicates/dedup_cache.dart';
import 'package:kemlock_core/features/duplicates/dedup_tagger.dart';
import 'package:kemlock_core/features/duplicates/duplicate_merge.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

const _day = 24 * 60 * 60 * 1000;

Login _login(
  String id, {
  String name = 'Proton',
  String username = 'sam',
  String? password = 'one',
  List<WebsiteRule>? uris,
  List<String>? websites,
  String? note,
  String? spaceId,
  int at = 1000,
  List<PreviousPassword>? previous,
  List<String>? tags,
}) => Login(
  id: id,
  name: name,
  username: username,
  password: password,
  websites: websites,
  uris: uris,
  note: note,
  spaceId: spaceId,
  addedAt: at,
  previousPasswords: previous,
  tags: tags,
);

List<DedupItem> _items(List<Login> logins) => dedupItems(logins: logins);

MergeChoices _choices(List<Login> logins, {Set<String> readOnly = const {}}) => MergeChoices(_items(logins), readOnlySlots: readOnly);

Login _merged(MergeChoices choices, [int now = 9000]) => choices.merged(now) as Login;

void main() {
  group('the item that stays', () {
    test('is the newest copy, and the other goes', () {
      final choices = _choices([_login('a', at: 1000), _login('b', at: 2000)]);

      expect(choices.kept.id, 'b');
      expect(choices.removed.map((item) => item.id), ['a']);
    });

    test('is the space\'s copy across places, whichever is newer', () {
      final choices = _choices([_login('a', at: 5000), _login('b', spaceId: 'team', at: 1000)]);

      expect(choices.acrossPlaces, isTrue);
      expect(choices.kept.id, 'b');
    });

    test('can be picked, which puts every pick back to the newest', () {
      final choices = _choices([_login('a', name: 'Old', at: 1000), _login('b', name: 'New', at: 2000)]);
      final name = choices.differing.first;

      final other = choices.withPick(name, 'a').withKept('a');

      expect(other.kept.id, 'a');
      expect(_merged(other).name, 'New');
    });

    test('is left as it is when the person can\'t change it, and only the other copy goes', () {
      final choices = _choices(
        [_login('a', name: 'Vault name', at: 5000), _login('b', name: 'Space name', spaceId: 'team', at: 1000)],
        readOnly: {spaceSlot('team')},
      );

      expect(choices.keptIsReadOnly, isTrue);
      expect(choices.differing, isEmpty);
      expect(_merged(choices).name, 'Space name');
      expect(choices.removed.map((item) => item.id), ['a']);
    });

    test('needs two items', () {
      expect(() => MergeChoices(_items([_login('a')])), throwsArgumentError);
    });
  });

  group('the fields', () {
    test('that differ are the only ones listed, and the newest value is preselected', () {
      final choices = _choices([_login('a', name: 'proton.me', at: 1000), _login('b', name: 'Proton Mail', at: 2000)]);

      expect(choices.differing.map((field) => field.id), ['name']);
      expect(choices.pickFor(choices.differing.single).id, 'b');
      expect(_merged(choices).name, 'Proton Mail');
    });

    test('take another pick, which changes the result', () {
      final choices = _choices([_login('a', name: 'proton.me', at: 1000), _login('b', name: 'Proton Mail', at: 2000)]);
      final picked = choices.withPick(choices.differing.single, 'a');

      expect(_merged(picked).name, 'proton.me');
    });

    test('prefer the newest value that is not empty', () {
      final choices = _choices([_login('a', note: 'recovery email', at: 1000), _login('b', note: null, at: 2000)]);

      expect(_merged(choices).note, 'recovery email');
    });

    test('are the same kind\'s own: a note\'s title and text, a code\'s issuer and label', () {
      final notes = MergeChoices(
        dedupItems(
          notes: [
            const SecureNote(id: 'a', title: 'Old', text: 'same', addedAt: 1),
            const SecureNote(id: 'b', title: 'New', text: 'same', addedAt: 2),
          ],
        ),
      );
      final codes = MergeChoices(
        dedupItems(
          accounts: [
            OtpAccount(id: 'a', issuer: 'Google', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1),
            OtpAccount(id: 'b', issuer: 'google.com', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 2),
          ],
        ),
      );

      expect(notes.differing.map((field) => field.id), ['title']);
      expect((notes.merged(9) as SecureNote).title, 'New');
      expect(codes.differing.map((field) => field.id), ['issuer']);
      expect((codes.merged(9) as OtpAccount).issuer, 'google.com');
    });
  });

  group('a login', () {
    test('keeps the union of the websites', () {
      final choices = _choices([
        _login('a', websites: ['proton.me'], at: 1000),
        _login('b', websites: ['account.proton.me'], at: 2000),
      ]);

      expect(_merged(choices).websites, ['account.proton.me', 'proton.me']);
    });

    test('keeps the narrower rule when one address has two', () {
      final choices = _choices([
        _login('a', uris: const [WebsiteRule('proton.me', match: WebsiteMatch.baseDomain)], at: 1000),
        _login('b', uris: const [WebsiteRule('proton.me', match: WebsiteMatch.exact)], at: 2000),
        _login('c', uris: const [WebsiteRule('proton.me')], at: 500),
      ]);

      expect(_merged(choices).rules, const [WebsiteRule('proton.me', match: WebsiteMatch.exact)]);
    });

    test('keeps the regular expressions apart', () {
      final choices = _choices([
        _login('a', uris: const [WebsiteRule(r'^https://mail\..*', match: WebsiteMatch.regularExpression)], at: 1000),
        _login(
          'b',
          uris: const [
            WebsiteRule(r'^https://.*\.proton\.me', match: WebsiteMatch.regularExpression),
            WebsiteRule('proton.me'),
          ],
          at: 2000,
        ),
      ]);

      expect(_merged(choices).rules, hasLength(3));
    });

    test('loses no password: the one not kept is the first previous password', () {
      final choices = _choices([_login('a', password: 'old', at: 1000), _login('b', password: 'new', at: 2000)]);

      final merged = _merged(choices);

      expect(merged.password, 'new');
      expect(merged.previousPasswords!.map((previous) => previous.password), ['old']);
      expect(merged.previousPasswords!.first.until, 9000);
    });

    test('keeps a password that is already a previous one only once, and five at most', () {
      final kept = _login(
        'b',
        password: 'new',
        at: 2000,
        previous: [for (var i = 0; i < 5; i++) PreviousPassword(password: 'p$i', until: 100 - i)],
      );
      final choices = _choices([_login('a', password: 'p0', at: 1000), kept]);

      final merged = _merged(choices);

      expect(merged.previousPasswords, hasLength(5));
      expect(merged.previousPasswords!.where((previous) => previous.password == 'p0'), hasLength(1));
    });

    test('takes the other password when it is picked, and the old one is kept', () {
      final choices = _choices([_login('a', password: 'old', at: 1000), _login('b', password: 'new', at: 2000)]);
      final password = choices.differing.firstWhere((field) => field.id == 'password');

      final merged = _merged(choices.withPick(password, 'a'));

      expect(merged.password, 'old');
      expect(merged.previousPasswords!.map((previous) => previous.password), ['new']);
    });

    test('keeps the tags of every copy', () {
      final choices = _choices([
        _login('a', tags: ['work'], at: 1000),
        _login('b', tags: ['mail'], at: 2000),
      ]);

      expect(_merged(choices).tags, unorderedEquals(['work', 'mail']));
    });
  });

  group('a code', () {
    test('keeps the highest HOTP counter', () {
      final choices = MergeChoices(
        dedupItems(
          accounts: [
            OtpAccount(id: 'a', type: OtpType.hotp, issuer: 'A', label: 'me', secret: 'JBSWY3DPEHPK3PXP', counter: 12, addedAt: 1),
            OtpAccount(id: 'b', type: OtpType.hotp, issuer: 'A', label: 'me', secret: 'JBSWY3DPEHPK3PXP', counter: 9, addedAt: 2),
          ],
        ),
      );

      expect((choices.merged(9) as OtpAccount).counter, 12);
    });
  });

  group('a merge record', () {
    test('reads back as it was written, with keys it does not know', () {
      final record = MergeRecord(
        id: 'm1',
        at: 5,
        kind: 'login',
        kept: _login('a').toJson(),
        removed: [_login('b').toJson()],
        relinked: [_login('c').toJson()],
        extra: const {'later': true},
      );

      final read = MergeRecord.fromJson(record.toJson())!;

      expect(read.toJson(), record.toJson());
      expect(mergeItemOf('login', read.kept), _login('a'));
      expect(mergeKindOf(_login('a')), 'login');
    });

    test('is not read from anything else, and an unknown kind gives no item', () {
      expect(MergeRecord.fromJson('x'), isNull);
      expect(MergeRecord.fromJson({'id': 'm'}), isNull);
      expect(mergeItemOf('later', const {}), isNull);
    });

    test('can be undone for 30 days and not after', () {
      final record = MergeRecord(id: 'm', at: 0, kind: 'login', kept: const {}, removed: const []);

      expect(record.undoable(6 * _day), isTrue);
      expect(record.undoable(30 * _day - 1), isTrue);
      expect(record.undoable(30 * _day), isFalse);
      expect(record.undoable(31 * _day), isFalse);
    });

    test('keeps every kind of item as it was', () {
      const note = SecureNote(id: 'n', title: 'T', text: 'x', addedAt: 1);
      final service = BackupService(
        id: 's',
        serviceName: 'S',
        codes: const [BackupCode(code: '1')],
        addedAt: 1,
      );
      const passkey = Passkey(id: 'p', credentialId: 'c', rpId: 'example.com', userHandle: 'h', userName: 'u', privateKey: 'k', addedAt: 1);

      for (final item in <Object>[note, service, passkey]) {
        expect(mergeItemOf(mergeKindOf(item), mergeJsonOf(item)), item);
      }
    });
  });
}
