@TestOn('vm')
library;

import 'package:kemlock_core/features/import/import_merge.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:test/test.dart';

Login _login(
  String id, {
  String username = 'ada',
  String? password = 'pw-1',
  List<String> websites = const ['larkspur.example'],
  int addedAt = 1,
}) => Login(id: id, name: 'Larkspur', username: username, password: password, websites: websites, addedAt: addedAt);

OtpAccount _code(String id, String issuer, {String secret = 'JBSWY3DPEHPK3PXP'}) =>
    OtpAccount(id: id, issuer: issuer, label: 'ada', secret: secret, addedAt: 1);

Passkey _passkey(String id, {String credentialId = 'AQID', String rpId = 'larkspur.example'}) =>
    Passkey(id: id, credentialId: credentialId, rpId: rpId, userHandle: 'AQ', userName: 'ada', privateKey: 'key', addedAt: 1);

PaymentCard _card(String id, String number, {int month = 4, int year = 2029}) =>
    PaymentCard(id: id, name: 'Visa', number: number, expMonth: month, expYear: year, addedAt: 1);

ImportPreview _preview({
  List<Login> logins = const [],
  List<OtpAccount> accounts = const [],
  List<Passkey> passkeys = const [],
  List<PaymentCard> cards = const [],
}) => ImportPreview(accounts: accounts, backupServices: const [], logins: logins, passkeys: passkeys, cards: cards);

String Function() _ids() {
  var next = 0;
  return () => 'new-${next++}';
}

void main() {
  group('logins', () {
    test('a login with the same site, username and password is a match, skipped unless chosen otherwise', () {
      final held = [_login('h1')];
      final preview = _preview(logins: [_login('i1')]);

      final skip = planLogins(preview, held);
      expect(skip.matches.map((m) => (m.held.id, m.incoming.id)), [('h1', 'i1')]);
      expect(skip.adds, isEmpty);
      expect(skip.replaces, isEmpty);

      expect(planLogins(preview, held, choose: (_) => DuplicateChoice.keepBoth).adds.map((l) => l.id), ['i1']);
      expect(planLogins(preview, held, choose: (_) => DuplicateChoice.replace).replaces.map((r) => r.held.id), ['h1']);
    });

    test('a login with the same site and username but another password is imported, not matched', () {
      final plan = planLogins(_preview(logins: [_login('i1', password: 'pw-2')]), [_login('h1')]);

      expect(plan.adds.map((l) => l.id), ['i1']);
      expect(plan.matches, isEmpty);
    });

    test('a login whose site differs, or whose username differs only in case, is judged by the shared rules', () {
      final held = [_login('h1', username: 'Ada')];

      expect(planLogins(_preview(logins: [_login('i1', username: 'ada')]), held).matches, hasLength(1));
      expect(
        planLogins(
          _preview(
            logins: [
              _login('i2', websites: const ['other.example']),
            ],
          ),
          held,
        ).adds,
        hasLength(1),
      );
    });

    test('keep both beside a match by id gives the copy a new id', () {
      final plan = planLogins(
        _preview(logins: [_login('h1')]),
        [_login('h1')],
        choose: (_) => DuplicateChoice.keepBoth,
        newId: _ids(),
      );

      expect(plan.adds.map((l) => l.id), ['new-0']);
    });

    test('a replaced login keeps its old password first among its previous passwords', () {
      final held = _login('h1', password: 'old').copyWith(passwordChangedAt: 10);
      final incoming = _login('i1', password: 'new').copyWith(name: 'Larkspur Mail', note: 'moved');

      final replaced = replacingLogin(held, incoming, 100);

      expect(replaced.id, 'h1');
      expect(replaced.addedAt, held.addedAt);
      expect(replaced.name, 'Larkspur Mail');
      expect(replaced.note, 'moved');
      expect(replaced.password, 'new');
      expect(replaced.passwordChangedAt, 100);
      expect(replaced.previousPasswords!.first.password, 'old');
      expect(replaced.previousPasswords!.first.until, 100);
    });

    test('a replaced login whose import has no password keeps its own', () {
      final replaced = replacingLogin(_login('h1', password: 'old'), _login('i1', password: null), 100);

      expect(replaced.password, 'old');
      expect(replaced.previousPasswords, isNull);
    });
  });

  group('codes, passkeys and cards', () {
    test('"Google" and "Gmail" with one secret match', () {
      final plan = planCodes(_preview(accounts: [_code('i1', 'Google')]), [_code('h1', 'Gmail')]);

      expect(plan.matches.map((m) => (m.held.issuer, m.incoming.issuer)), [('Gmail', 'Google')]);
      expect(plan.adds, isEmpty);
    });

    test('keep both adds a second copy of a code, and a code with another secret is just added', () {
      final preview = _preview(
        accounts: [
          _code('i1', 'Google'),
          _code('i2', 'Other', secret: 'GEZDGNBVGY3TQOJQ'),
        ],
      );

      final plan = planCodes(preview, [_code('h1', 'Gmail')], choose: (_) => DuplicateChoice.keepBoth);

      expect(plan.adds.map((a) => a.id), ['i1', 'i2']);
    });

    test('a replaced HOTP code takes the higher counter', () {
      final held = OtpAccount(id: 'h1', type: OtpType.hotp, issuer: 'A', label: 'a', secret: 'JBSWY3DPEHPK3PXP', counter: 9, addedAt: 1);
      final incoming = OtpAccount(
        id: 'i1',
        type: OtpType.hotp,
        issuer: 'B',
        label: 'b',
        secret: 'JBSWY3DPEHPK3PXP',
        counter: 4,
        addedAt: 2,
      );

      final replaced = replacingCode(held, incoming, 50);

      expect((replaced.id, replaced.issuer, replaced.counter, replaced.addedAt), ('h1', 'B', 9, 1));
    });

    test('a passkey matches on relying party and credential id', () {
      final held = [_passkey('h1')];

      expect(planPasskeys(_preview(passkeys: [_passkey('i1')]), held).matches, hasLength(1));
      expect(planPasskeys(_preview(passkeys: [_passkey('i2', credentialId: 'BAUG')]), held).adds, hasLength(1));
      expect(planPasskeys(_preview(passkeys: [_passkey('i3', rpId: 'other.example')]), held).adds, hasLength(1));
    });

    test('a card matches on its digits and expiry, however the number was typed', () {
      final held = [_card('h1', '4111111111111111')];

      expect(planCards(_preview(cards: [_card('i1', '4111111111111111')]), held).matches, hasLength(1));
      expect(planCards(_preview(cards: [_card('i4', '4111 1111-1111 1111')]), held).matches, hasLength(1));
      expect(planCards(_preview(cards: [_card('i2', '4111111111111111', month: 5)]), held).adds, hasLength(1));
      expect(planCards(_preview(cards: [_card('i3', '4242424242424242')]), held).adds, hasLength(1));
    });

    test('a repeat of one imported id is taken once', () {
      final plan = planCards(_preview(cards: [_card('i1', '4242424242424242'), _card('i1', '4242424242424242')]), []);

      expect(plan.adds, hasLength(1));
    });
  });
}
