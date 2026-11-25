@TestOn('vm')
library;

import 'package:kemlock_core/features/backup/backup_codes.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:test/test.dart';

void main() {
  group('parseCodes', () {
    test('splits one code per line', () {
      expect(parseCodes('abcde-12345\nfghij-67890\r\nklmno-13579'), ['abcde-12345', 'fghij-67890', 'klmno-13579']);
    });

    test('keeps two-group codes such as Google’s "1234 5678" whole', () {
      expect(parseCodes('1234 5678\n2345 6789'), ['1234 5678', '2345 6789']);
    });

    test('splits two-column pastes with single spaces', () {
      expect(parseCodes('abcde-12345 fghij-67890\nklmno-13579 pqrst-24680'), ['abcde-12345', 'fghij-67890', 'klmno-13579', 'pqrst-24680']);
    });

    test('splits columns separated by several spaces or tabs, keeping grouped codes', () {
      expect(parseCodes('1234 5678    2345 6789\n3456 7890\t4567 8901'), ['1234 5678', '2345 6789', '3456 7890', '4567 8901']);
    });

    test('accepts comma or space separated lists on one line', () {
      expect(parseCodes('aaaaaa, bbbbbb cccccc'), ['aaaaaa', 'bbbbbb', 'cccccc']);
    });

    test('drops blanks and duplicates', () {
      expect(parseCodes('\n abc123 \n\nabc123\n'), ['abc123']);
    });
  });

  group('isLow', () {
    BackupService service(List<bool> used) => BackupService(
      id: 's',
      serviceName: 'S',
      addedAt: 0,
      codes: [for (final (i, u) in used.indexed) BackupCode(code: '$i', used: u)],
    );

    test('is low at two or fewer unused codes', () {
      expect(isLow(service([true, false, false])), isTrue);
      expect(isLow(service([false, false, false])), isFalse);
    });

    test('is not low for a service without codes', () {
      expect(isLow(service([])), isFalse);
    });
  });

  group('markCode', () {
    final now = DateTime.fromMillisecondsSinceEpoch(1234);

    test('remembers when a code was used', () {
      expect(markCode(const BackupCode(code: 'a'), used: true, now: now).toJson(), {'code': 'a', 'used': true, 'usedAt': 1234});
    });

    test('forgets the date when a code is marked unused again', () {
      final code = markCode(const BackupCode(code: 'a', used: true, usedAt: 1234), used: false, now: now);

      expect(code.toJson(), {'code': 'a', 'used': false});
      expect(code.usedAt, isNull);
    });

    test('keeps the keys a newer version wrote on the code', () {
      const code = BackupCode(code: 'a', extra: {'note': 'n'});

      expect(markCode(code, used: true, now: now).extra, {'note': 'n'});
      expect(markCode(code, used: false, now: now).extra, {'note': 'n'});
    });
  });
}
