import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart' show ZLibDecoderWeb, ZLibEncoderWeb;

import '../core/ids.dart';
import '../crypto/aes_gcm.dart';
import '../crypto/bytes.dart';
import '../crypto/kdf.dart';
import '../models/backup_service.dart';
import '../models/otp_account.dart';

// QR transfer (the app's `qr_transfer.dart`, with zlib from `package:archive` in place of `dart:io`): a vault moved between devices as one or more QR codes, as
// `qrVault.ts` writes them.
//
//  1. Accounts are written with short field names and serialised as JSON.
//  2. The JSON is compressed with raw deflate.
//  3. PBKDF2-SHA256 (200,000 rounds) derives an AES-256-GCM key from the
//     transfer password, which encrypts the compressed JSON.
//  4. salt (16) || iv (12) || ciphertext is split into chunks of at most
//     2,048 bytes, one per QR code: `BMC1:<index>/<total>:<base64url>`.
//
// A plain transfer skips 2 and 3 and starts its chunks with `BMCP`.

const qrMagic = 'BMC1';
const qrMagicPlaintext = 'BMCP';
const _maxBytesPerChunk = 2048;
const _pbkdf2Iterations = 200000;

/// One scanned QR code of a transfer.
class QrChunk {
  const QrChunk({required this.index, required this.total, required this.payload});

  /// 1-based.
  final int index;
  final int total;
  final Uint8List payload;
}

/// What a transfer brought over: new ids, added now.
class QrTransfer {
  const QrTransfer({required this.accounts, required this.backupServices});

  final List<OtpAccount> accounts;
  final List<BackupService> backupServices;
}

/// The codes can't be read. [message] is the text the dialog shows, as `qrVault.ts` worded it.
class QrTransferError implements Exception {
  const QrTransferError(this.message);

  final String message;

  @override
  String toString() => message;
}

/// The most codes one transfer is read from: 2 MB of vault. A scanned code
/// names the total itself, and the import screen draws a tag for each.
const maxQrChunks = 999;

/// The leading integer of [text], as JavaScript's `parseInt(text, 10)` reads
/// it, or null for NaN and for more digits than an int holds.
int? _parseInt(String text) {
  final match = RegExp(r'^\s*([+-]?\d+)').firstMatch(text);
  return match == null ? null : int.tryParse(match.group(1)!);
}

QrChunk? _parseChunk(String data, String magic) {
  if (!data.startsWith('$magic:')) return null;
  final rest = data.substring(magic.length + 1); // "01/03:<b64>"
  final slash = rest.indexOf('/');
  final colon = rest.indexOf(':');
  if (slash < 0 || colon < 0 || colon <= slash) return null;
  final index = _parseInt(rest.substring(0, slash));
  final total = _parseInt(rest.substring(slash + 1, colon));
  if (index == null || total == null) return null;
  if (total < 1 || total > maxQrChunks || index < 1 || index > total) return null;
  return QrChunk(index: index, total: total, payload: unb64url(rest.substring(colon + 1)));
}

/// The chunk a scanned encrypted (`BMC1`) code holds, or null for anything else.
QrChunk? parseQrChunk(String data) => _parseChunk(data, qrMagic);

/// The chunk a scanned plain (`BMCP`) code holds, or null for anything else.
QrChunk? parseQrChunkPlaintext(String data) => _parseChunk(data, qrMagicPlaintext);

/// True for an encrypted `BMC1` chunk, false for anything else, such as a plain `BMCP` one.
bool isEncryptedQrChunk(String data) => data.startsWith('$qrMagic:');

/// An account as a transfer holds it. `qrVault.ts` wrote and read the six
/// keys `i` to `p`, as every version since does, and no others. A Steam or
/// HOTP account also writes its type in `t`, and an HOTP one its counter in
/// `c`; a reader that doesn't know them passes over them and reads the
/// account as TOTP, as before. A TOTP account is written as it always was.
Map<String, Object?> _compactAccount(OtpAccount a) => {
  'i': a.issuer,
  'l': a.label,
  's': a.secret,
  'a': a.algorithm,
  'd': a.digits,
  'p': a.period,
  if (a.kind != OtpType.totp) 't': a.kind.name,
  if (a.kind == OtpType.hotp && a.counter != null) 'c': a.counter,
};

/// The type a transfer gives an account: Steam or HOTP from `t`, and null,
/// TOTP, for anything else, as for a transfer written before `t`.
OtpType? _type(Object? value) => switch (OtpType.parse(value)) {
  OtpType.totp || null => null,
  final type => type,
};

/// An HOTP account's counter from `c`, when it is a count.
int? _counter(Object? value) => value is int && value >= 0 ? value : null;

Uint8List _compactJson(List<OtpAccount> accounts, List<BackupService> backupServices) => utf8.encode(
  jsonEncode({
    'a': [for (final a in accounts) _compactAccount(a)],
    'b': [
      for (final s in backupServices)
        {
          'n': s.serviceName,
          'c': [for (final c in s.codes) c.toJson()],
        },
    ],
  }),
);

List<String> _chunk(Uint8List bytes, String magic) {
  final total = bytes.isEmpty ? 1 : (bytes.length / _maxBytesPerChunk).ceil();
  final tot = total.toString().padLeft(2, '0');
  return [
    for (var i = 0; i < total; i++)
      '$magic:${(i + 1).toString().padLeft(2, '0')}/$tot:'
          '${b64url(bytes.sublist(i * _maxBytesPerChunk, ((i + 1) * _maxBytesPerChunk).clamp(0, bytes.length)))}',
  ];
}

/// Encrypts the accounts and services and splits them into QR code strings:
/// one for most vaults, a few for large ones.
Future<List<String>> exportVaultQr(List<OtpAccount> accounts, List<BackupService> backupServices, String password) async {
  final compressed = Uint8List.fromList(const ZLibEncoderWeb().encodeBytes(_compactJson(accounts, backupServices), raw: true));
  final salt = randomBytes(16);
  final key = await pbkdf2Sha256InBackground(utf8.encode(password), salt, _pbkdf2Iterations, 32);
  final sealed = await aesGcmEncrypt(key, compressed);
  final blob = concatBytes([salt, sealed.nonce, sealed.ct]);
  // An encrypted blob is never empty, so this always makes at least one chunk
  return _chunk(blob, qrMagic);
}

/// The accounts and services in a plain transfer's QR code strings.
List<String> exportVaultQrPlaintext(List<OtpAccount> accounts, List<BackupService> backupServices) =>
    _chunk(_compactJson(accounts, backupServices), qrMagicPlaintext);

Uint8List _reassemble(List<QrChunk> parsed, String magic) {
  if (parsed.isEmpty) throw QrTransferError('No valid $magic QR chunks provided.');
  final total = parsed.first.total;
  final have = {for (final c in parsed) c.index};
  if (have.length != total) {
    final missing = [
      for (var i = 1; i <= total; i++)
        if (!have.contains(i)) i,
    ];
    throw QrTransferError('Missing QR code(s): ${missing.join(', ')} of $total.');
  }
  final sorted = [...parsed]..sort((a, b) => a.index.compareTo(b.index));
  return concatBytes([for (final c in sorted) c.payload]);
}

QrTransfer _expand(Object? payload, int now) {
  // Old transfers hold the compact accounts alone; newer ones { a, b }
  final compactAccounts = payload is List ? payload : (payload is Map ? payload['a'] as List<Object?>? : null) ?? const [];
  final compactServices = payload is Map ? (payload['b'] as List<Object?>?) ?? const [] : const [];
  return QrTransfer(
    accounts: [
      for (final a in compactAccounts.cast<Map<String, Object?>>())
        OtpAccount(
          id: newUuid(),
          type: _type(a['t']),
          issuer: a['i'] as String? ?? '',
          label: a['l'] as String? ?? '',
          secret: a['s'] as String? ?? '',
          algorithm: a['a'] as String? ?? 'SHA1',
          digits: (a['d'] as num?)?.toInt() ?? 6,
          period: (a['p'] as num?)?.toInt() ?? 30,
          counter: _type(a['t']) == OtpType.hotp ? _counter(a['c']) : null,
          addedAt: now,
        ),
    ],
    backupServices: [
      for (final s in compactServices.cast<Map<String, Object?>>())
        BackupService(
          id: newUuid(),
          serviceName: s['n'] as String? ?? '',
          codes: [for (final c in (s['c'] as List<Object?>?) ?? const []) BackupCode.fromJson(c! as Map<String, Object?>)],
          addedAt: now,
        ),
    ],
  );
}

/// Reassembles and decrypts a transfer's QR code strings. Throws
/// [QrTransferError] for missing codes or a wrong password.
Future<QrTransfer> importVaultQr(List<String> chunks, String password, {DateTime? now}) async {
  final blob = _reassemble([...chunks.map(parseQrChunk).nonNulls], qrMagic);
  final salt = blob.sublist(0, 16);
  final iv = blob.sublist(16, 28);
  final ciphertext = blob.sublist(28);
  final key = await pbkdf2Sha256InBackground(utf8.encode(password), salt, _pbkdf2Iterations, 32);
  final Uint8List compressed;
  try {
    compressed = await aesGcmDecrypt(key, iv, ciphertext);
  } on AesGcmAuthError {
    throw const QrTransferError('Wrong password or corrupted QR data.');
  }
  final json = utf8.decode(const ZLibDecoderWeb().decodeBytes(compressed, raw: true));
  return _expand(jsonDecode(json), (now ?? DateTime.now()).millisecondsSinceEpoch);
}

/// Reassembles a plain transfer's QR code strings. Throws [QrTransferError] for missing codes.
Future<QrTransfer> importVaultQrPlaintext(List<String> chunks, {DateTime? now}) async {
  final blob = _reassemble([...chunks.map(parseQrChunkPlaintext).nonNulls], qrMagicPlaintext);
  return _expand(jsonDecode(utf8.decode(blob)), (now ?? DateTime.now()).millisecondsSinceEpoch);
}
