// The vault's logins as a CSV file in Bitwarden's layout, which nearly every password manager reads, and the codes as a list of
// otpauth:// links, which every authenticator reads (and so does Kemlock, as `importers.dart`'s "uris"). Plain text: the caller
// shows its warning before it writes either, as for the plain JSON export.
//
// New in Kemlock-core: the app exports its own JSON, encrypted or plain, and Credential Exchange; it has no CSV or link list.
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/secure_note.dart';
import '../accounts/otpauth.dart';

/// Bitwarden's header, which the CSV importer (`formats/csv_logins.dart`) reads back.
const loginCsvHeader = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp';

final _needsQuotes = RegExp('[",\r\n]');

/// What a spreadsheet takes for a formula when a cell starts with it: `=`, `+`, `-`, `@`, a tab or a carriage return.
final _formula = RegExp(r'^[=+\-@\t\r]');

/// [text] as a cell: a leading formula character gets a `'` before it (the reader, `csv_logins.dart`, takes it off again), unless the
/// cell is a password, which is written exactly as it is.
String _field(String? value, {bool exact = false}) {
  var text = value ?? '';
  if (!exact && _formula.hasMatch(text)) text = "'$text";
  return _needsQuotes.hasMatch(text) ? '"${text.replaceAll('"', '""')}"' : text;
}

/// Column [exact] of [fields] is written as it is (the password); the others are guarded against formulas.
String _row(List<String?> fields, {int exact = -1}) =>
    [for (final (i, field) in fields.indexed) _field(field, exact: i == exact)].join(',');

/// [logins] and [notes] as CSV. Every cell but the password is guarded against being run as a spreadsheet formula: a leading `'` goes
/// before `=`, `+`, `-`, `@`, a tab or a carriage return, and the reader takes it off again. The password is written exactly as it is,
/// so one that starts with such a character is as it was (the caller's warning says so). Each login has its linked code in `login_totp`
/// (an otpauth:// link; Steam as `steam://`, and none for an HOTP code, which Bitwarden's fields can't carry). A tag becomes the
/// folder, the first of them, nested as `A/B`.
String exportLoginsCsv(List<Login> logins, List<OtpAccount> accounts, {List<SecureNote> notes = const []}) {
  final byId = {for (final account in accounts) account.id: account};
  String? folder(List<String>? tags) => tags == null || tags.isEmpty ? null : tags.first.replaceAll(' / ', '/');
  final lines = [loginCsvHeader];
  for (final login in logins) {
    final code = byId[login.accountId];
    String? totp;
    if (code != null) {
      try {
        totp = buildBitwardenTotp(code);
      } on FormatException {
        totp = null;
      }
    }
    lines.add(
      _row([
        folder(login.tags),
        login.isPinned ? '1' : '',
        'login',
        login.name,
        login.note,
        '',
        '0',
        [for (final rule in login.rules) rule.uri].join('\n'),
        login.username,
        login.password,
        totp,
      ], exact: 9),
    );
  }
  for (final note in notes) {
    lines.add(_row([folder(note.tags), '', 'note', note.title, note.text, '', '0', '', '', '', '']));
  }
  return '${lines.join('\n')}\n';
}

/// What [exportCodeLinks] wrote: the text, how many links, and how many codes were left out because their secret isn't one.
class CodeLinks {
  const CodeLinks({required this.text, required this.exported, required this.skipped});

  final String text;
  final int exported;
  final int skipped;
}

/// [accounts] as one otpauth:// link a line, as Aegis and every authenticator read them.
CodeLinks exportCodeLinks(List<OtpAccount> accounts) {
  final lines = <String>[];
  var skipped = 0;
  for (final account in accounts) {
    try {
      lines.add(buildOtpUri(account));
    } on FormatException {
      skipped++;
    }
  }
  return CodeLinks(text: lines.isEmpty ? '' : '${lines.join('\n')}\n', exported: lines.length, skipped: skipped);
}
