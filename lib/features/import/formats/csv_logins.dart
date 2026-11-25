// The logins other password managers export as CSV: Chrome, Edge, Brave, Firefox, Safari, Bitwarden, 1Password, LastPass,
// NordPass, KeePass and Dashlane's, which all write a header row of column names and one login per row. Columns are found by
// name, in any order, so a manager that adds one is still read; a row's kind comes from a `type` column when there is one
// (Bitwarden's, NordPass's) and from LastPass's `http://sn` address for a note.
//
// This is new in Kemlock-core; the app's importers (importers.dart) read authenticator exports and Credential Exchange files and
// no CSV (the add-credential-exchange plan leaves it for a later plan), so the app's own sheet doesn't offer it yet. Pure Dart.
import '../../../core/ids.dart';
import '../../../models/login.dart';
import '../../../models/otp_account.dart';
import '../../../models/secure_note.dart';
import '../../../models/website_rule.dart';
import '../../accounts/otpauth.dart';
import '../importers.dart';
import 'import_extras.dart';

/// The most rows a CSV file is read for, and the most text in one: a file over either is refused as not a CSV of logins.
const maxCsvRows = 50000;
const maxCsvLength = 64 * 1024 * 1024;

/// [text] split into records of fields, as RFC 4180 reads it: quoted fields may hold the delimiter, line breaks and doubled quotes.
/// A leading byte order mark goes. The delimiter is a comma, or the semicolon or tab that the header line holds more of.
List<List<String>> parseCsv(String text) {
  final source = text.startsWith('\u{FEFF}') ? text.substring(1) : text;
  final delimiter = _delimiterOf(source);
  final rows = <List<String>>[];
  var row = <String>[];
  final field = StringBuffer();
  var quoted = false;
  var started = false;

  void endField() {
    row.add(field.toString());
    field.clear();
    started = false;
  }

  void endRow() {
    endField();
    // A blank line is no record
    if (row.length > 1 || row.first.isNotEmpty) rows.add(row);
    row = <String>[];
  }

  for (var i = 0; i < source.length; i++) {
    final char = source[i];
    if (quoted) {
      if (char == '"') {
        if (i + 1 < source.length && source[i + 1] == '"') {
          field.write('"');
          i++;
        } else {
          quoted = false;
        }
      } else {
        field.write(char);
      }
      continue;
    }
    if (char == '"' && !started) {
      quoted = true;
      started = true;
    } else if (char == delimiter) {
      endField();
    } else if (char == '\n' || char == '\r') {
      if (char == '\r' && i + 1 < source.length && source[i + 1] == '\n') i++;
      endRow();
    } else {
      field.write(char);
      started = true;
    }
    if (rows.length > maxCsvRows) throw const ImportError(ImportErrorCode.unsupported);
  }
  if (started || field.isNotEmpty || row.isNotEmpty) endRow();
  return rows;
}

String _delimiterOf(String text) {
  final end = text.indexOf('\n');
  final line = end < 0 ? text : text.substring(0, end);
  var inQuotes = false;
  final counts = {',': 0, ';': 0, '\t': 0};
  for (final char in line.split('')) {
    if (char == '"') {
      inQuotes = !inQuotes;
    } else if (!inQuotes && counts.containsKey(char)) {
      counts[char] = counts[char]! + 1;
    }
  }
  final best = counts.entries.reduce((a, b) => b.value > a.value ? b : a);
  return best.value == 0 ? ',' : best.key;
}

String _key(String header) => header.toLowerCase().replaceAll(RegExp('[^a-z0-9]'), '');

// The names each field goes by, as _key reads them, the likelier first
const _nameColumns = ['name', 'title', 'accountname', 'service', 'account'];
const _urlColumns = ['url', 'loginuri', 'website', 'loginurl', 'uri', 'weburl', 'webaddress', 'siteurl', 'hostname', 'origin'];
const _userColumns = ['username', 'loginusername', 'loginname', 'userid', 'user', 'login', 'email', 'emailaddress'];
const _passwordColumns = ['password', 'loginpassword', 'pass', 'passwd'];
const _noteColumns = ['notes', 'note', 'extra', 'comments', 'comment', 'memo'];
const _totpColumns = ['totp', 'logintotp', 'otpauth', 'otp', 'otpsecret', 'authenticator', '2fa', 'twofactor'];
const _folderColumns = ['folder', 'grouping', 'group', 'category', 'collection'];
const _typeColumns = ['type', 'itemtype'];
const _favoriteColumns = ['favorite', 'fav', 'favourite'];

/// The column of the first of [names] the header holds, or null.
int? _column(Map<String, int> header, List<String> names) {
  for (final name in names) {
    final at = header[name];
    if (at != null) return at;
  }
  return null;
}

Map<String, int> _header(List<String> row) {
  final header = <String, int>{};
  for (final (index, name) in row.indexed) {
    header.putIfAbsent(_key(name), () => index);
  }
  return header;
}

/// Whether [text] is a CSV of logins: its first record names a password column, and a site, a name or a user beside it.
bool looksLikeLoginCsv(String text) {
  if (text.length > maxCsvLength) return false;
  final end = text.indexOf('\n');
  // Only the header is read to tell: a JSON file or a list of links has none
  final head = end < 0 ? text : text.substring(0, end);
  if (head.contains('{') || head.contains('://')) return false;
  final List<List<String>> rows;
  try {
    rows = parseCsv(head);
  } on ImportError {
    return false;
  }
  if (rows.isEmpty) return false;
  final header = _header(rows.first);
  return _column(header, _passwordColumns) != null &&
      (_column(header, _urlColumns) != null || _column(header, _nameColumns) != null || _column(header, _userColumns) != null);
}

/// The cell at [at], without the space around it, unless [exact]: a password and a note are kept as they were written.
String _cell(List<String> row, int? at, {bool exact = false}) {
  if (at == null || at >= row.length) return '';
  return exact ? row[at] : row[at].trim();
}

final _hostOfUrl = RegExp(r'^(?:[A-Za-z][A-Za-z0-9+.-]*://)?([^/?#:]+)');

/// Bitwarden writes several addresses of a login in one cell, a line each; others a single one.
List<String> _urls(String cell) => [
  for (final line in cell.split(RegExp(r'[\r\n]+')))
    if (line.trim().isNotEmpty) line.trim(),
];

List<String> _tags(String folder) {
  final cleaned = folder.split('/').map((part) => part.trim()).where((part) => part.isNotEmpty).join(' / ');
  return cleaned.isEmpty ? const [] : [cleaned];
}

bool _truthy(String value) => const {'1', 'true', 'yes'}.contains(value.toLowerCase());

/// The logins (and notes, and the codes of logins that hold one) of a CSV file. Each gets a new id and [now] (epoch ms, the clock
/// by default) as its time added, so the caller has nothing to set. A row that is a card or an identity, or holds nothing, is
/// counted in [ForeignImport.skipped]; a login whose code can't be read keeps the login, with the code listed in
/// [ForeignImport.skips]. Throws an [ImportError] when [text] is no CSV of logins.
ForeignImport readLoginCsv(String text, {String Function()? newId, int? now}) {
  if (!looksLikeLoginCsv(text)) throw const ImportError(ImportErrorCode.unsupported);
  final makeId = newId ?? newUuid;
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  final rows = parseCsv(text);
  final header = _header(rows.first);
  final name = _column(header, _nameColumns);
  final url = _column(header, _urlColumns);
  final user = _column(header, _userColumns);
  final password = _column(header, _passwordColumns);
  final note = _column(header, _noteColumns);
  final totp = _column(header, _totpColumns);
  final folder = _column(header, _folderColumns);
  final type = _column(header, _typeColumns);
  final favorite = _column(header, _favoriteColumns);

  final logins = <Login>[];
  final accounts = <OtpAccount>[];
  final notes = <SecureNote>[];
  final skips = <ImportSkip>[];
  var skipped = 0;
  for (final row in rows.skip(1)) {
    final kind = _cell(row, type).toLowerCase();
    final address = _cell(row, url);
    final title = _cell(row, name);
    final username = _cell(row, user);
    final secret = _cell(row, password, exact: true);
    final body = _cell(row, note, exact: true);
    final tags = _tags(_cell(row, folder));
    // LastPass keeps a secure note as a row whose address is http://sn; Bitwarden and NordPass say so in a type column
    if (kind == 'note' || kind == 'securenote' || kind == 'secure note' || address == 'http://sn') {
      if (title.isEmpty && body.isEmpty) {
        skipped++;
        continue;
      }
      notes.add(SecureNote(id: makeId(), title: title.isEmpty ? '—' : title, text: body, tags: tags.isEmpty ? null : tags, addedAt: at));
      continue;
    }
    if (kind.isNotEmpty && kind != 'login' && kind != 'password') {
      skipped++;
      continue;
    }
    if (title.isEmpty && address.isEmpty && username.isEmpty && secret.isEmpty) {
      skipped++;
      continue;
    }
    final urls = _urls(address);
    final host = urls.isEmpty ? null : _hostOfUrl.firstMatch(urls.first)?.group(1);
    final loginName = title.isNotEmpty ? title : (host ?? (username.isNotEmpty ? username : '—'));
    final rules = [for (final one in urls) WebsiteRule(one)];
    String? accountId;
    final code = _cell(row, totp);
    if (code.isNotEmpty) {
      final parsed = parseBitwardenTotp(code, name: loginName, username: username);
      if (parsed == null) {
        skips.add(ImportSkip(loginName, SkipReason.totpSecret));
      } else {
        accountId = makeId();
        accounts.add(parsed.copyWith(id: accountId, addedAt: at));
      }
    }
    logins.add(
      Login(
        id: makeId(),
        name: loginName,
        username: username.isEmpty ? null : username,
        password: secret.isEmpty ? null : secret,
        websites: rules.isEmpty ? null : fillHosts(rules),
        uris: rules.isEmpty ? null : rules,
        note: body.isEmpty ? null : body,
        tags: tags.isEmpty ? null : tags,
        pinned: _truthy(_cell(row, favorite)) ? true : null,
        accountId: accountId,
        addedAt: at,
      ),
    );
  }
  return ForeignImport(
    source: ImportSource.csv,
    accounts: accounts,
    skipped: skipped,
    logins: logins,
    notes: notes,
    skips: skips,
  );
}
