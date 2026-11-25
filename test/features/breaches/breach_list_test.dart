@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/breaches/breach_list.dart';
import 'package:test/test.dart';

// test/fixtures/breaches/hibp-breaches.json is 21 of the breaches Have I Been Pwned's
// https://haveibeenpwned.com/api/v3/breaches returned on 2026-11-15, each object as the
// API gave it. Among them are the kinds the list leaves out: unverified (126, AntiPublic,
// Zoosk), of no one service (AntiPublic, AlienStealerLogs, CastleRAT), spam lists (Digimon,
// LinkedInScrape2023), a stealer log (AlienStealerLogs), malware (CastleRAT), retired
// (VTech) and fabricated (Zoosk). It is the API's answer, so it is never written by hand.
List<Object?> hibpFixture() => jsonDecode(File('test/fixtures/breaches/hibp-breaches.json').readAsStringSync()) as List<Object?>;

void main() {
  group("trimming Have I Been Pwned's answer", () {
    final list = BreachList.fromHibp(hibpFixture(), updated: '2026-11-15');

    test('keeps the verified breaches of a service with a domain', () {
      expect(
        [for (final breach in list.entries) breach.name],
        [
          'Adobe',
          'Canva',
          'Dropbox',
          'Duolingo',
          'Facebook',
          'InternetArchive',
          'Kickstarter',
          'Lastfm',
          'LinkedIn',
          'Patreon',
          'Trello',
          'Twitter',
          'Twitter200M',
        ],
      );
    });

    for (final (name, why) in [
      ('126', 'unverified'),
      ('AntiPublic', 'of no one service'),
      ('Digimon', 'a spam list'),
      ('LinkedInScrape2023', 'a spam list'),
      ('AlienStealerLogs', 'a stealer log'),
      ('CastleRAT', 'malware'),
      ('VTech', 'retired'),
      ('Zoosk', 'fabricated'),
    ]) {
      test('leaves out $name, which is $why', () {
        expect(hibpFixture().any((breach) => (breach! as Map<String, Object?>)['Name'] == name), isTrue);
        expect(list.has(name), isFalse);
      });
    }

    test('keeps the name, domain, dates, size and whether passwords were taken', () {
      expect(list.of('Adobe').single.toRow(), ['Adobe', 'Adobe', 'adobe.com', '2013-10-04', '2013-12-04', 152445165, 1]);
      expect(list.of('Trello').single.toRow(), ['Trello', 'Trello', 'trello.com', '2024-01-16', '2024-01-22', 15111945, 0]);
      expect(list.of('Adobe').single.passwords, isTrue);
      expect(list.of('Trello').single.passwords, isFalse);
    });

    test('says where the data is from and under which licence', () {
      expect(list.source, 'https://haveibeenpwned.com');
      expect(list.updated, '2026-11-15');
      expect(list.license, allOf(contains('Have I Been Pwned'), contains('Creative Commons Attribution 4.0')));
    });

    test('reads back what it writes', () {
      final read = BreachList.fromJson(jsonDecode(jsonEncode(list.toJson())) as Map<String, Object?>);

      expect(read.toJson(), list.toJson());
      expect(read.of('twitter.com'), list.of('twitter.com'));
    });
  });

  group('finding the breaches of a service', () {
    final list = BreachList.fromHibp(hibpFixture(), updated: '2026-11-15');

    for (final name in ['Adobe', 'Adobe Inc.', 'adobe.com', 'ADOBE', 'https://account.adobe.com/security', 'Adobe (work)']) {
      test('finds the Adobe breach for "$name"', () {
        expect([for (final breach in list.of(name)) breach.name], ['Adobe']);
      });
    }

    for (final name in ['Twitter', 'Twitter, Inc.', 'twitter.com']) {
      test('finds both breaches of Twitter for "$name", the earliest listed first', () {
        expect([for (final breach in list.of(name)) breach.name], ['Twitter', 'Twitter200M']);
      });
    }

    test('finds a service by a domain that is not its name', () {
      expect(list.of('archive.org').single.name, 'InternetArchive');
      expect(list.of('Internet Archive').single.name, 'InternetArchive');
      expect(list.of('last.fm').single.name, 'Lastfm');
    });

    test('finds nothing for a service that is not in the list', () {
      expect(list.of('GitHub'), isEmpty);
      expect(list.of(''), isEmpty);
    });
  });

  group('the trimmed list', () {
    const adobe = ['Adobe', 'Adobe', 'adobe.com', '2013-10-04', '2013-12-04', 152445165, 1];

    BreachList read(List<Object?> entries) =>
        BreachList.fromJson({'source': 's', 'updated': '2026-11-15', 'license': 'l', 'entries': entries});

    test('skips a row it cannot read', () {
      final list = read([
        adobe,
        ['Short', 'Short', 'short.com'],
        ['NoDomain', 'No Domain', '', '2020-01-01', '2020-01-02', 5, 0],
        ['BadDate', 'Bad Date', 'bad.com', 'last year', '2020-01-02', 5, 0],
        ['BadCount', 'Bad Count', 'bad.com', '2020-01-01', '2020-01-02', 'many', 0],
        'not a row',
        null,
      ]);

      expect([for (final breach in list.entries) breach.name], ['Adobe']);
    });

    test('reads a row a later version added values to', () {
      final list = read([
        [...adobe, 'unverified', 42],
      ]);

      expect(list.entries.single.toRow(), adobe);
    });

    test('keeps one breach of a name', () {
      expect(read([adobe, adobe]).entries, hasLength(1));
    });

    test('reads nothing from a file without entries', () {
      expect(BreachList.fromJson(const {}).entries, isEmpty);
      expect(BreachList.fromJson(const {'entries': 'none'}).entries, isEmpty);
      expect(BreachList.empty.of('Adobe'), isEmpty);
    });

    test('counts a breach as listed by the end of its day', () {
      final breach = read([adobe]).entries.single;

      expect(breach.listedBy, DateTime.utc(2013, 12, 5).millisecondsSinceEpoch);
      expect(breach.year, 2013);
      expect(breach.happened, DateTime.utc(2013, 10, 4));
    });
  });
}
