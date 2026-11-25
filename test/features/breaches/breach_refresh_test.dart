@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/core/storage/key_value_store.dart';
import 'package:kemlock_core/features/breaches/breach_list.dart';
import 'package:kemlock_core/features/breaches/breach_refresh.dart';
import 'package:kemlock_core/vault/vault_registry.dart';
import 'package:test/test.dart';

import 'breach_list_test.dart' show hibpFixture;
import 'fake_hibp.dart';

Map<String, Object?> _named(String name) => hibpFixture().cast<Map<String, Object?>>().firstWhere((breach) => breach['Name'] == name);

/// A breach Have I Been Pwned lists after the fixture was taken.
Map<String, Object?> _newBreach(String name, String domain) => {..._named('Trello'), 'Name': name, 'Title': name, 'Domain': domain};

void main() {
  // The phone's list: the fixture without Trello, as bundled on 2026-11-01
  final withoutTrello = [
    for (final breach in hibpFixture())
      if ((breach! as Map<String, Object?>)['Name'] != 'Trello') breach,
  ];
  final bundled = BreachList.fromHibp(withoutTrello, updated: '2026-11-01');
  // What the service has now: the same, and Trello listed last
  final listed = [...withoutTrello, _named('Trello')];

  late KeyValueStore store;
  late FakeHibp hibp;
  var now = DateTime.utc(2026, 11, 15, 9);

  BreachRefresh refresh({Duration? timeout}) => BreachRefresh(
    client: hibp.client,
    userAgent: () async => 'Kemlock/1.1.0',
    store: store,
    now: () => now,
    timeout: timeout ?? const Duration(seconds: 30),
  );

  setUp(() {
    store = KeyValueStore.memory();
    hibp = FakeHibp(listed);
    now = DateTime.utc(2026, 11, 15, 9);
  });

  test('takes the list when the latest breach is one the phone does not know', () async {
    expect(await refresh().run(bundled), isTrue);

    expect(hibp.asked, ['/api/v3/latestbreach', '/api/v3/breaches']);
    final stored = refresh().stored()!;
    expect(stored.has('Trello'), isTrue);
    expect(stored.updated, '2026-11-15');
    expect(stored.license, breachLicense);
    expect(stored.entries, hasLength(bundled.entries.length + 1));
    expect(refresh().inUse(bundled), isNot(same(bundled)));
    expect(refresh().inUse(bundled).of('Trello'), isNotEmpty);
  });

  test('asks for nothing more when the phone already has the latest breach', () async {
    final current = BreachList.fromHibp(listed, updated: '2026-11-10');

    expect(await refresh().run(current), isFalse);

    expect(hibp.asked, ['/api/v3/latestbreach']);
    expect(refresh().stored(), isNull);
    expect(refresh().inUse(current), same(current));
  });

  test('names the app in both requests and sends nothing else', () async {
    await refresh().run(bundled);

    for (final request in hibp.requests) {
      expect(request.method, 'GET');
      expect(request.url.host, 'haveibeenpwned.com');
      expect(request.url.query, isEmpty);
      expect(request.body, isEmpty);
      expect(request.headers.keys.map((key) => key.toLowerCase()), ['user-agent']);
      expect(request.headers['User-Agent'], 'Kemlock/1.1.0');
    }
  });

  test('does not ask again within a day of a check, and does after it', () async {
    await refresh().run(bundled);
    final current = refresh().inUse(bundled);
    hibp.requests.clear();

    now = now.add(const Duration(hours: 23, minutes: 59));
    expect(await refresh().run(current), isFalse);
    expect(hibp.requests, isEmpty);

    now = now.add(const Duration(minutes: 2));
    expect(await refresh().run(current), isFalse);
    expect(hibp.asked, ['/api/v3/latestbreach']);
  });

  test('checks again when the clock was set back before the last check', () async {
    await refresh().run(bundled);
    hibp.requests.clear();

    now = now.subtract(const Duration(days: 3));
    await refresh().run(refresh().inUse(bundled));

    expect(hibp.asked, ['/api/v3/latestbreach']);
  });

  test('takes the list once when the latest breach is one the list leaves out', () async {
    // A stealer log listed last: never in the app's list
    hibp.breaches = [...listed, _named('AlienStealerLogs')];

    expect(await refresh().run(bundled), isTrue);
    expect(refresh().stored()!.has('Trello'), isTrue);
    expect(refresh().stored()!.has('AlienStealerLogs'), isFalse);

    // The next day it is still the latest: nothing more is fetched
    hibp.requests.clear();
    now = now.add(const Duration(days: 1, minutes: 1));
    expect(await refresh().run(refresh().inUse(bundled)), isFalse);
    expect(hibp.asked, ['/api/v3/latestbreach']);
  });

  test('stores nothing when the only news is a breach the list leaves out', () async {
    final current = BreachList.fromHibp(listed, updated: '2026-11-10');
    hibp.breaches = [...listed, _named('AlienStealerLogs')];

    expect(await refresh().run(current), isFalse);

    expect(hibp.asked, ['/api/v3/latestbreach', '/api/v3/breaches']);
    expect(refresh().stored(), isNull);
  });

  test('takes a later breach on a later day', () async {
    await refresh().run(bundled);
    now = now.add(const Duration(days: 2));
    hibp.breaches = [...listed, _newBreach('Example2026', 'example.com')];

    expect(await refresh().run(refresh().inUse(bundled)), isTrue);

    final stored = refresh().stored()!;
    expect(stored.updated, '2026-11-17');
    expect(stored.of('example.com').single.name, 'Example2026');
  });

  group('a check that fails changes nothing and is tried again', () {
    Future<void> expectUnchanged() async {
      expect(await refresh().run(bundled), isFalse);
      expect(refresh().stored(), isNull);
      expect(refresh().inUse(bundled), same(bundled));
      expect(store.getItem(keyBreachCheck), isNull);
      // Not counted as a check: the next one asks again at once
      hibp.requests.clear();
      await refresh().run(bundled);
      expect(hibp.requests, isNotEmpty);
    }

    test('offline', () async {
      hibp.offline = true;
      await expectUnchanged();
    });

    test('an error from the service', () async {
      hibp.status = 503;
      await expectUnchanged();
    });

    test('a list that is not JSON', () async {
      hibp.body = '<html>Just a moment...</html>';
      await expectUnchanged();
    });

    test('a list that is not a list', () async {
      hibp.body = '{"message":"rate limited"}';
      await expectUnchanged();
    });

    test('a list with under half the breaches the phone has', () async {
      hibp.body = jsonEncode([_named('Adobe'), _named('Trello')]);
      await expectUnchanged();
    });

    test('a list larger than the limit', () async {
      hibp.body = jsonEncode([...listed, 'x' * (BreachRefresh.maxBytes + 1)]);
      await expectUnchanged();
    });

    test('a list that never ends, which is dropped at the limit', () async {
      final chunk = Uint8List(64 * 1024);
      var sent = 0;
      Stream<List<int>> endless() async* {
        while (true) {
          sent += chunk.length;
          yield chunk;
        }
      }

      final endlessList = BreachRefresh(
        client: MockClient.streaming(
          (request, _) async => request.url.path == '/api/v3/latestbreach'
              ? http.StreamedResponse(Stream.value(utf8.encode(jsonEncode(_named('Trello')))), 200)
              : http.StreamedResponse(endless(), 200),
        ),
        userAgent: () async => 'Kemlock/1.1.0',
        store: store,
        now: () => now,
      );

      expect(await endlessList.run(bundled), isFalse);
      expect(sent, lessThanOrEqualTo(BreachRefresh.maxBytes + 2 * chunk.length));
      expect(store.getItem(keyBreachCheck), isNull);
      expect(store.getItem(keyBreachList), isNull);
    });

    test('no answer in time', () async {
      final slow = BreachRefresh(
        client: MockClient((_) => Future.delayed(const Duration(seconds: 5), () => http.Response('{}', 200))),
        userAgent: () async => 'Kemlock',
        store: store,
        now: () => now,
        timeout: const Duration(milliseconds: 20),
      );

      expect(await slow.run(bundled), isFalse);
      expect(store.getItem(keyBreachCheck), isNull);
      expect(store.getItem(keyBreachList), isNull);
    });
  });

  test('uses the bundled list when it is later than the stored one, as after an app update', () async {
    await refresh().run(bundled);
    final newer = BreachList.fromHibp(listed, updated: '2026-12-01');

    expect(refresh().inUse(newer), same(newer));
  });

  test('uses a list stored on the day the bundled one was made', () async {
    final today = BreachList.fromHibp(withoutTrello, updated: '2026-11-15');

    expect(await refresh().run(today), isTrue);

    expect(refresh().inUse(today).has('Trello'), isTrue);
  });

  test('a reset removes the stored list and the record of the last check', () async {
    await refresh().run(bundled);
    expect(store.getItem(keyBreachList), isNotNull);
    expect(store.getItem(keyBreachCheck), isNotNull);

    VaultRegistry(store).removeAllVaults();

    expect(store.getItem(keyBreachList), isNull);
    expect(store.getItem(keyBreachCheck), isNull);
    expect(refresh().inUse(bundled), same(bundled));
  });

  test('deleting a vault leaves the stored list, which is the device\'s', () async {
    await refresh().run(bundled);

    VaultRegistry(store).removeVaultData(mainVault);

    expect(refresh().stored()!.has('Trello'), isTrue);
    expect(store.getItem(keyBreachCheck), isNotNull);
  });

  test('reads no list from storage that does not hold one', () {
    for (final raw in ['', 'not json', '[]', '{"entries":[]}', '{"entries":"none"}']) {
      store.setItem(keyBreachList, raw);
      expect(refresh().stored(), isNull, reason: raw);
      expect(refresh().inUse(bundled), same(bundled));
    }
  });

  test('checks again when what was recorded of the last check cannot be read', () async {
    store.setItem(keyBreachCheck, 'not json');

    await refresh().run(BreachList.fromHibp(listed, updated: '2026-11-10'));

    expect(hibp.asked, ['/api/v3/latestbreach']);
    expect(jsonDecode(store.getItem(keyBreachCheck)!), {'at': now.millisecondsSinceEpoch, 'latest': 'Trello'});
  });
}
