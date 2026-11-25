import '../../models/backup_service.dart';
import '../../models/json.dart';

final _lineBreaks = RegExp(r'[\r\n]+');
final _columns = RegExp(r'[,\t]+|\s{2,}');
final _spaces = RegExp(r'\s+');

/// Splits pasted text into unique codes. Codes may be separated by newlines,
/// commas, tabs or spaces, but a piece made of exactly two short groups
/// ("1234 5678", as Google prints them) is kept as one code.
List<String> parseCodes(String text) {
  final codes = <String>[];
  for (final line in text.split(_lineBreaks)) {
    for (final piece in line.split(_columns)) {
      final parts = [
        for (final part in piece.split(_spaces))
          if (part.isNotEmpty) part,
      ];
      if (parts.length == 2 && parts.every((p) => p.length <= 5)) {
        codes.add(parts.join(' '));
      } else {
        codes.addAll(parts);
      }
    }
  }
  return codes.toSet().toList();
}

/// A service is "low" when two or fewer codes remain.
bool isLow(BackupService s) => s.codes.isNotEmpty && s.codes.where((c) => !c.used).length <= 2;

/// Marks a code used, remembering [now] as when, or unused, forgetting when.
/// Keys a newer version wrote on the code are kept either way.
BackupCode markCode(BackupCode code, {required bool used, required DateTime now}) =>
    code.copyWith(used: used, usedAt: used ? now.millisecondsSinceEpoch : unset);
