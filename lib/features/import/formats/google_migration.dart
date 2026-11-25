// The codes as Google Authenticator's "Transfer accounts" QR codes: `otpauth-migration://offline?data=<base64 of a protobuf>`,
// the writing half of `parseGoogleMigration` (importers.dart), from Google's `migration.proto`:
//
//   MigrationPayload { repeated OtpParameters otp_parameters = 1; int32 version = 2; int32 batch_size = 3;
//                      int32 batch_index = 4; int32 batch_id = 5; }
//   OtpParameters { bytes secret = 1; string name = 2; string issuer = 3; Algorithm algorithm = 4; DigitCount digits = 5;
//                   OtpType type = 6; int64 counter = 7; }
//
// The format has no period and no Steam type, so a code with another period, another digit count than six or eight, an algorithm
// other than SHA-1, SHA-256 or SHA-512, or a Steam code can't be written without changing what it computes: it is left out, and
// listed, never written wrong. Pure Dart, like the reader.
import 'dart:convert';
import 'dart:typed_data';

import '../../../models/otp_account.dart';
import '../../accounts/otp.dart';

/// Why a code isn't in the QR codes.
enum MigrationLeftOutReason {
  /// A Steam code: the format has no such type.
  steam,

  /// A time-based code whose period isn't 30 seconds, which the format can't say.
  period,

  /// A code of other than six or eight digits.
  digits,

  /// A code whose algorithm isn't SHA-1, SHA-256 or SHA-512.
  algorithm,

  /// A secret that isn't Base32.
  secret,

  /// A code whose name and issuer are so long that it does not fit a QR code even alone.
  tooLong,
}

/// One code the QR codes leave out.
class MigrationLeftOut {
  const MigrationLeftOut(this.title, this.reason);

  final String title;
  final MigrationLeftOutReason reason;
}

/// What [buildGoogleMigration] made: one URI per QR code, how many codes they hold, and what was left out.
class GoogleMigration {
  const GoogleMigration({required this.uris, required this.exported, required this.leftOut});

  final List<String> uris;
  final int exported;
  final List<MigrationLeftOut> leftOut;
}

/// The most codes one QR code holds, as Google's own app writes them.
const migrationBatchSize = 10;

/// The most bytes of payload one QR code holds: with its base64 and the URI around it, a code the reader still finds (a QR code
/// holds 2,953 bytes at most, and a phone's camera reads a dense one badly).
const migrationBatchBytes = 1100;

/// The most characters of one transfer URI: what a QR code of the standard's largest version holds (2,953 bytes), with room to spare.
const migrationMaxUri = 2400;

const _algorithms = {'SHA1': 1, 'SHA256': 2, 'SHA512': 3};

Uint8List _varint(int value) {
  final out = <int>[];
  var rest = value;
  while (rest >= 0x80) {
    out.add((rest & 0x7f) | 0x80);
    rest >>= 7;
  }
  out.add(rest);
  return Uint8List.fromList(out);
}

void _number(BytesBuilder out, int field, int value) {
  out
    ..add(_varint(field << 3))
    ..add(_varint(value));
}

void _bytes(BytesBuilder out, int field, List<int> value) {
  out
    ..add(_varint((field << 3) | 2))
    ..add(_varint(value.length))
    ..add(value);
}

MigrationLeftOutReason? _problem(OtpAccount account) {
  if (account.kind == OtpType.steam) return MigrationLeftOutReason.steam;
  if (!_algorithms.containsKey(account.algorithm.toUpperCase())) return MigrationLeftOutReason.algorithm;
  if (account.digits != 6 && account.digits != 8) return MigrationLeftOutReason.digits;
  if (account.kind == OtpType.totp && account.period != 30) return MigrationLeftOutReason.period;
  try {
    if (base32Decode(account.secret).isEmpty) return MigrationLeftOutReason.secret;
  } on FormatException {
    return MigrationLeftOutReason.secret;
  }
  return null;
}

Uint8List _parameters(OtpAccount account) {
  final out = BytesBuilder();
  _bytes(out, 1, base32Decode(account.secret));
  final issuer = account.issuer;
  // Google writes the name as "Issuer:account"; the reader takes the issuer's prefix off again
  _bytes(out, 2, utf8.encode(issuer.isEmpty ? account.label : '$issuer:${account.label}'));
  if (issuer.isNotEmpty) _bytes(out, 3, utf8.encode(issuer));
  _number(out, 4, _algorithms[account.algorithm.toUpperCase()]!);
  _number(out, 5, account.digits == 8 ? 2 : 1);
  final hotp = account.kind == OtpType.hotp;
  _number(out, 6, hotp ? 1 : 2);
  if (hotp) _number(out, 7, account.counter ?? 0);
  return out.toBytes();
}

Uint8List _payload(List<Uint8List> parameters, {required int size, required int index, required int batchId}) {
  final out = BytesBuilder();
  for (final one in parameters) {
    _bytes(out, 1, one);
  }
  _number(out, 2, 1);
  _number(out, 3, size);
  _number(out, 4, index);
  _number(out, 5, batchId);
  return out.toBytes();
}

typedef _Entry = ({OtpAccount account, Uint8List parameters});

String _uri(List<Uint8List> batch, {required int size, required int index, required int batchId}) {
  final data = base64.encode(_payload(batch, size: size, index: index, batchId: batchId));
  return 'otpauth-migration://offline?data=${Uri.encodeQueryComponent(data)}';
}

/// [batch] as the batches that each fit one QR code: itself when its URI is short enough, else its two halves, down to one code. A
/// single code that is still too long comes back alone, for the caller to leave out.
List<List<_Entry>> _fitting(List<_Entry> batch) {
  // The URI's length is the same whatever the batch's place, within a few characters the limit leaves room for
  final length = _uri([for (final entry in batch) entry.parameters], size: 99, index: 99, batchId: 0x7fffffff).length;
  if (length <= migrationMaxUri || batch.length == 1) return [batch];
  final middle = batch.length ~/ 2;
  return [..._fitting(batch.sublist(0, middle)), ..._fitting(batch.sublist(middle))];
}

/// [accounts] as Google Authenticator's transfer QR codes, in batches of at most [migrationBatchSize] codes and
/// [migrationBatchBytes] bytes, each split further when its URI is more than [migrationMaxUri] characters, so that every URI fits one
/// QR code. A code too long to fit alone is left out and listed. [batchId] ties the batches of one export together, as the apps that
/// read several do.
GoogleMigration buildGoogleMigration(List<OtpAccount> accounts, {int batchId = 0}) {
  final leftOut = <MigrationLeftOut>[];
  final batches = <List<_Entry>>[];
  var current = <_Entry>[];
  var bytes = 0;
  for (final account in accounts) {
    final problem = _problem(account);
    if (problem != null) {
      leftOut.add(MigrationLeftOut(account.issuer.isNotEmpty ? account.issuer : account.label, problem));
      continue;
    }
    final entry = (account: account, parameters: _parameters(account));
    final size = entry.parameters.length;
    if (current.isNotEmpty && (current.length >= migrationBatchSize || bytes + size > migrationBatchBytes)) {
      batches.add(current);
      current = [];
      bytes = 0;
    }
    current.add(entry);
    bytes += size;
  }
  if (current.isNotEmpty) batches.add(current);

  final fitted = <List<_Entry>>[];
  for (final batch in batches) {
    for (final part in _fitting(batch)) {
      if (part.length == 1 && _uri([part.single.parameters], size: 99, index: 99, batchId: 0x7fffffff).length > migrationMaxUri) {
        final account = part.single.account;
        leftOut.add(MigrationLeftOut(account.issuer.isNotEmpty ? account.issuer : account.label, MigrationLeftOutReason.tooLong));
      } else {
        fitted.add(part);
      }
    }
  }
  return GoogleMigration(
    uris: [
      for (final (index, batch) in fitted.indexed)
        _uri([for (final entry in batch) entry.parameters], size: fitted.length, index: index, batchId: batchId),
    ],
    exported: fitted.fold(0, (sum, batch) => sum + batch.length),
    leftOut: leftOut,
  );
}
