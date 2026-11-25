@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/breaches/pwned_passwords.dart';
import 'package:test/test.dart';

// SHA-1("password") is 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
const _prefix = '5BAA6';
const _suffix = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

/// A Pwned Passwords answer of [lines], and what was asked of it.
class _Service {
  _Service(this.lines, {this.status = 200});

  final List<String> lines;
  final int status;
  final requests = <http.Request>[];

  late final client = MockClient((request) async {
    requests.add(request);
    return http.Response(lines.join('\r\n'), status);
  });

  PwnedPasswords get check => PwnedPasswords(client, userAgent: () async => 'Kemlock/1.1.0');
}

Matcher get _cannotTell => throwsA(isA<LeakCheckError>());

void main() {
  test('asks for the five characters the hash begins with, and for nothing else of it', () async {
    final service = _Service(['0018A45C4D1DEF81644B54AB7F969B88D65:1', '$_suffix:3861493']);

    expect(await service.check.timesLeaked('password'), 3861493);

    final request = service.requests.single;
    expect(request.method, 'GET');
    expect(request.url.toString(), 'https://api.pwnedpasswords.com/range/$_prefix');
    expect(request.body, isEmpty);
    // All of the request but the host, whose name has "password" in it
    final sent = '${request.url.path} ${request.url.query} ${request.headers} ${request.body}'.toUpperCase();
    expect(sent, isNot(contains(_suffix)));
    expect(sent, isNot(contains(_suffix.substring(0, 6))));
    expect(sent, isNot(contains('PASSWORD')));
  });

  test('asks for a padded answer and names the app', () async {
    final service = _Service(const []);

    await service.check.timesLeaked('password');

    expect(service.requests.single.headers['Add-Padding'], 'true');
    expect(service.requests.single.headers['User-Agent'], 'Kemlock/1.1.0');
  });

  test('hashes the password as typed, in UTF-8', () async {
    const password = 'pässwörd ✓ ';
    final hash = sha1.convert(utf8.encode(password)).toString().toUpperCase();
    final service = _Service(['${hash.substring(5)}:7']);

    expect(await service.check.timesLeaked(password), 7);
    expect(service.requests.single.url.path, '/range/${hash.substring(0, 5)}');
  });

  test('finds the suffix in either case, and with space around it', () async {
    expect(await _Service(['${_suffix.toLowerCase()}:12']).check.timesLeaked('password'), 12);
    expect(await _Service([' $_suffix : 12 ']).check.timesLeaked('password'), 12);
  });

  test('a password that is not in the answer has not leaked', () async {
    final service = _Service(['0018A45C4D1DEF81644B54AB7F969B88D65:1', '00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2']);

    expect(await service.check.timesLeaked('password'), 0);
  });

  test('an entry added as padding, with a count of zero, is no match', () async {
    expect(await _Service(['$_suffix:0']).check.timesLeaked('password'), 0);
  });

  test('skips a line it cannot read', () async {
    final service = _Service(['', 'not a line', ':5', '$_suffix:many', '$_suffix:42']);

    expect(await service.check.timesLeaked('password'), 42);
  });

  test('cannot tell when the service answers with an error', () async {
    for (final status in [403, 429, 500, 503]) {
      await expectLater(_Service(['$_suffix:9'], status: status).check.timesLeaked('password'), _cannotTell, reason: '$status');
    }
  });

  test('cannot tell when there is no connection', () async {
    final check = PwnedPasswords(MockClient((_) async => throw http.ClientException('offline')), userAgent: () async => 'Kemlock');

    await expectLater(check.timesLeaked('password'), _cannotTell);
  });

  test('cannot tell when no answer comes in time', () async {
    final never = Completer<http.Response>();
    final check = PwnedPasswords(
      MockClient((_) => never.future),
      userAgent: () async => 'Kemlock',
      timeout: const Duration(milliseconds: 20),
    );

    await expectLater(check.timesLeaked('password'), _cannotTell);
  });

  test('waits ten seconds for the answer unless told otherwise', () {
    expect(
      PwnedPasswords(MockClient((_) async => http.Response('', 200)), userAgent: () async => 'Kemlock').timeout,
      const Duration(seconds: 10),
    );
  });

  test('cannot tell from an answer far larger than a padded one', () async {
    final service = _Service([for (var i = 0; i < 30000; i++) '${i.toRadixString(16).padLeft(35, '0').toUpperCase()}:1', '$_suffix:9']);

    await expectLater(service.check.timesLeaked('password'), _cannotTell);
  });

  test('drops an answer that never ends once it is far larger than a padded one', () async {
    final lines = utf8.encode('0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n' * 1000);
    var sent = 0;
    Stream<List<int>> endless() async* {
      while (true) {
        sent += lines.length;
        yield lines;
      }
    }

    final check = PwnedPasswords(
      MockClient.streaming((request, _) async => http.StreamedResponse(endless(), 200)),
      userAgent: () async => 'Kemlock/1.1.0',
    );

    await expectLater(check.timesLeaked('password'), throwsA(isA<LeakCheckError>().having((e) => e.reason, 'reason', 'answer too large')));
    expect(sent, lessThanOrEqualTo((1 << 20) + 2 * lines.length));
  });

  test('cannot tell when the user agent is not there in time', () async {
    final never = Completer<String>();
    final check = PwnedPasswords(
      MockClient((_) async => http.Response('', 200)),
      userAgent: () => never.future,
      timeout: const Duration(milliseconds: 20),
    );

    await expectLater(check.timesLeaked('password'), _cannotTell);
  });

  test('cannot tell when the user agent cannot be had', () async {
    final check = PwnedPasswords(MockClient((_) async => http.Response('', 200)), userAgent: () async => throw StateError('no version'));

    await expectLater(check.timesLeaked('password'), _cannotTell);
  });
}
