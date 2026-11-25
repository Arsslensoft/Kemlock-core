// Opening a file to import, without a sheet: what the app's import sheet does between "choose a file" and "review what it holds"
// (`import_sheet.dart`'s `_detect`, `_readKemlock` and `_readForeign`), as functions that throw one [ImportReadError] for every way
// a file can fail to open. A host with another screen (the browser extension's transfer page) uses these, and the app should switch
// to them when it takes the rest of the import code from here.
//
// Pure Dart, no Flutter. Nothing here writes, logs or keeps a file's text.
import 'dart:convert';
import 'dart:typed_data';

import '../../core/ids.dart';
import '../../crypto/aes_gcm.dart';
import '../../vault/export_archive.dart';
import '../../vault/qr_transfer.dart';
import '../../vault/vault_export.dart';
import '../../vault/vault_store.dart' show DeriveKey, deriveVaultKey;
import 'formats/cxf.dart';
import 'import_merge.dart';
import 'importers.dart';

/// Why a file or a QR code couldn't be opened.
enum ImportProblem {
  /// Not a format Kemlock reads.
  unsupported,

  /// A known format with nothing in it Kemlock keeps.
  empty,

  /// The password doesn't open it (or none was given), or the encrypted part is damaged.
  badPassword,

  /// Bitwarden's encrypted export, which Kemlock can't read.
  bitwardenEncrypted,

  /// A Credential Exchange file over the size Kemlock reads.
  cxfTooLarge,

  /// A Credential Exchange file of a version Kemlock doesn't read.
  cxfVersion,

  /// A Credential Exchange file of the wrong shape.
  cxfMalformed,

  /// A `.zip` that isn't an export's: damaged, or holding what an export doesn't.
  archive,

  /// A QR transfer with codes missing.
  qrMissing,

  /// Anything else: the file is damaged.
  corrupt,
}

/// A file or QR code that can't be opened; [problem] says why, and nothing of the file is in it.
class ImportReadError implements Exception {
  const ImportReadError(this.problem);

  final ImportProblem problem;

  @override
  String toString() => 'ImportReadError(${problem.name})';
}

/// What a chosen file turned out to be: a Kemlock export when [source] is null, or another app's.
class DetectedImport {
  const DetectedImport(this.source, {required this.encrypted, this.exporter});

  final ImportSource? source;
  final bool encrypted;

  /// The exporter a Credential Exchange file names in its header.
  final String? exporter;

  bool get foreign => source != null;
}

/// A file's text as the importers read it, once the archive it may come in is opened.
class OpenedImport {
  const OpenedImport({required this.text, required this.archive});

  final String text;

  /// The archive an export with attached files comes in, when it did.
  final ExportArchive? archive;
}

/// The text of the file [bytes]: the export inside a `.zip` archive, or the bytes as UTF-8 text without a byte order mark.
/// Throws [ImportReadError] for an archive that can't be imported.
OpenedImport openImportFile(Uint8List bytes) {
  ExportArchive? archive;
  if (isExportArchive(bytes)) {
    try {
      archive = readExportArchive(bytes);
    } on ExportArchiveError {
      throw const ImportReadError(ImportProblem.archive);
    }
  }
  var text = archive?.exportJson ?? utf8.decode(bytes, allowMalformed: true);
  if (text.startsWith('\u{FEFF}')) text = text.substring(1);
  return OpenedImport(text: text, archive: archive);
}

/// What [text] is, without decrypting it: a Kemlock export (encrypted or plain) or something the importers read; null when it is
/// neither. An archive holds a Kemlock export or nothing this reads, so [archive] set drops another app's format.
DetectedImport? detectImport(String text, {bool archive = false}) {
  DetectedImport? found;
  try {
    found = DetectedImport(null, encrypted: isEncryptedExport(text));
  } catch (_) {
    // Not one of ours; maybe another app's
  }
  if (found == null) {
    final other = detectFormat(text);
    if (other != null) {
      final exporter = other.source == ImportSource.cxf ? _exporterOf(text) : null;
      found = DetectedImport(other.source, encrypted: other.encrypted, exporter: exporter);
    }
  }
  return archive && (found?.foreign ?? false) ? null : found;
}

/// The exporter named in the header of a Credential Exchange file.
String? _exporterOf(String text) {
  try {
    return switch (jsonDecode(text)) {
      final Map<String, Object?> json => cxfExporterName(json),
      _ => null,
    };
  } on FormatException {
    return null;
  }
}

/// [detected]'s file, [text], opened with [password] when it has one, as the preview of what it holds. Throws [ImportReadError].
/// Another app's accounts and passkeys get new ids and [now] (epoch ms, the clock by default) as their time added; Credential
/// Exchange and CSV files come with their own.
Future<ImportPreview> readImport(
  String text,
  DetectedImport detected, {
  String? password,
  DeriveKey deriveKey = deriveVaultKey,
  String Function()? newId,
  int? now,
}) async {
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  final makeId = newId ?? newUuid;
  try {
    if (!detected.foreign) {
      if (detected.encrypted && (password == null || password.isEmpty)) throw const ImportReadError(ImportProblem.badPassword);
      final payload = detected.encrypted ? await importVault(text, password!, deriveKey: deriveKey) : importVaultPlaintext(text);
      return ImportPreview.of(payload);
    }
    final typed = password == null || password.isEmpty ? null : password;
    final result = await parseForeignExport(text, password: typed, newId: newId, now: at);
    if (result.source == ImportSource.cxf || result.source == ImportSource.csv) return ImportPreview.ofForeign(result);
    return ImportPreview(
      accounts: [for (final account in result.accounts) account.copyWith(id: makeId(), addedAt: at)],
      backupServices: const [],
      skipped: result.skipped,
      passkeys: [
        for (final passkey in result.passkeys) passkey.copyWith(id: makeId(), addedAt: passkey.addedAt == 0 ? at : passkey.addedAt),
      ],
    );
  } on ImportReadError {
    rethrow;
  } on CxfException catch (error) {
    throw ImportReadError(switch (error.problem) {
      CxfProblem.tooLarge => ImportProblem.cxfTooLarge,
      CxfProblem.unsupportedVersion => ImportProblem.cxfVersion,
      CxfProblem.malformed => ImportProblem.cxfMalformed,
      _ => ImportProblem.unsupported,
    });
  } on ImportError catch (error) {
    throw ImportReadError(switch (error.code) {
      ImportErrorCode.unsupported => ImportProblem.unsupported,
      ImportErrorCode.empty => ImportProblem.empty,
      ImportErrorCode.passwordRequired || ImportErrorCode.badPassword => ImportProblem.badPassword,
      ImportErrorCode.bitwardenEncrypted => ImportProblem.bitwardenEncrypted,
    });
  } on AesGcmAuthError {
    throw const ImportReadError(ImportProblem.badPassword);
  } on ExportFileError {
    throw const ImportReadError(ImportProblem.unsupported);
  } catch (error) {
    // A wrong password can surface as a decryption error of the package under it; anything else is a damaged file
    throw ImportReadError('$error'.toLowerCase().contains('decrypt') ? ImportProblem.badPassword : ImportProblem.corrupt);
  }
}

/// What the QR codes [texts] hold, by kind.
enum QrKind {
  /// Nothing Kemlock reads.
  none,

  /// otpauth:// links and Google Authenticator's transfer codes.
  links,

  /// Kemlock's own transfer, encrypted with a password (`BMC1`).
  transfer,

  /// Kemlock's own transfer, plain (`BMCP`).
  transferPlain,
}

/// Which kind of codes [texts] are, by the first that reads.
QrKind detectQr(List<String> texts) {
  if (texts.any(isEncryptedQrChunk)) return QrKind.transfer;
  if (texts.any((text) => text.startsWith('BMCP:'))) return QrKind.transferPlain;
  final links = texts.join('\n');
  final found = detectFormat(links);
  return found != null && (found.source == ImportSource.uris || found.source == ImportSource.google) ? QrKind.links : QrKind.none;
}

/// The preview of the QR codes [texts] (their text, one per code): links and Google's transfer codes as another app's export,
/// Kemlock's transfer by its chunks, with [password] when it is encrypted. Throws [ImportReadError].
Future<ImportPreview> readQrImport(List<String> texts, {String? password, int? now}) async {
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  switch (detectQr(texts)) {
    case QrKind.none:
      throw const ImportReadError(ImportProblem.unsupported);
    case QrKind.links:
      final links = texts.join('\n');
      return readImport(links, detectImport(links)!, now: at);
    case QrKind.transfer || QrKind.transferPlain:
      try {
        final transfer = detectQr(texts) == QrKind.transfer
            ? await importVaultQr(texts, password ?? '', now: DateTime.fromMillisecondsSinceEpoch(at))
            : await importVaultQrPlaintext(texts, now: DateTime.fromMillisecondsSinceEpoch(at));
        return ImportPreview(accounts: transfer.accounts, backupServices: transfer.backupServices);
      } on QrTransferError catch (error) {
        final missing = error.message.startsWith('Missing') || error.message.startsWith('No valid');
        throw ImportReadError(missing ? ImportProblem.qrMissing : ImportProblem.badPassword);
      } catch (_) {
        throw const ImportReadError(ImportProblem.corrupt);
      }
  }
}
