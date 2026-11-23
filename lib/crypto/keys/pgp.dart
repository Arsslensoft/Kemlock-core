// OpenPGP messages: the one file the app imports to encrypt, decrypt,
// sign and verify, as `keys.dart` is for keys. The format parts are in
// `openpgp/`.
//
// Every call takes its data as bytes or as a file's path, and runs
// synchronously between its awaits: the app calls them from the PGP job's
// isolate (`features/pgp/pgp_job.dart`), never from the UI's. Each throws
// a [PgpException] and nothing else.
//
// Keys are given as the vault keeps them: a binary transferable public
// key for a recipient or a signer to check, a binary transferable secret
// key, with its passphrase when it keeps one, to sign or decrypt.

import 'dart:convert';
import 'dart:typed_data';

import 'key_error.dart';
import 'openpgp/armor.dart';
import 'openpgp/cleartext.dart';
import 'openpgp/data_signature.dart';
import 'openpgp/key_info.dart';
import 'openpgp/message.dart';
import 'openpgp/modes.dart';
import 'openpgp/opened_key.dart';
import 'openpgp/packets.dart';
import 'openpgp/pgp_error.dart';
import 'openpgp/pgp_files.dart';
import 'openpgp/s2k.dart';
import 'openpgp/secret_key.dart';
import 'openpgp/stream.dart';
import 'openpgp/stream_files.dart';
import 'openpgp/usable_keys.dart';

export 'openpgp/data_signature.dart' show SignatureResult, SignatureVerdict;
export 'openpgp/key_info.dart' show PgpKey, PgpKeyInfo;
export 'openpgp/message.dart' show EncryptedForm, MessageRandom;
export 'openpgp/pgp_error.dart' show PgpException, PgpKeyTrouble, PgpProblem;
export 'openpgp/secret_key.dart' show DelegatedSecret;

/// The most text taken in or shown: 1 MB. Longer decrypted text is given
/// as a file.
const maxPgpTextLength = 1024 * 1024;

/// The most a clear-signed text may be: it is held whole.
const maxCleartextLength = 16 * 1024 * 1024;

/// Data for a call: bytes at hand, or a file read by its path, 64 KiB at
/// a time.
class PgpData {
  const PgpData.bytes(Uint8List this.bytes) : path = null;

  const PgpData.file(String this.path) : bytes = null;

  final Uint8List? bytes;
  final String? path;

  int get length => bytes?.length ?? pgpFileLength(path!);
}

/// A secret key to sign or decrypt with: the binary transferable secret
/// key, and its passphrase when it keeps one and the person gave it.
class PgpSecretKey {
  const PgpSecretKey(this.transferableKey, {this.passphrase, this.elsewhere});

  final Uint8List transferableKey;
  final String? passphrase;

  /// For a key whose secret parts are on an OpenPGP card, its stub kept as
  /// [transferableKey]: where the private step is done (openspec:
  /// add-openpgp-card).
  final DelegatedSecret? elsewhere;
}

// ─── Opening an input ─────────────────────────────────────────────────────────

class _Input {
  _Input(this.source, this.armorType, this.length, this._file);

  /// Binary packets, the armor already taken off; for a clear-signed
  /// text, the text itself.
  final ByteSource source;

  /// The armor block's type, or null for binary input.
  final String? armorType;
  final int length;
  final FileSource? _file;

  void close() => _file?.close();
}

_Input _open(PgpData data, {void Function(int read)? onRead}) {
  final bytes = data.bytes;
  if (bytes != null) {
    final sniff = sniffArmor(bytes.length > pgpPieceSize ? Uint8List.sublistView(bytes, 0, pgpPieceSize) : bytes);
    if (sniff.type == null) return _Input(BytesSource(bytes), null, bytes.length, null);
    if (sniff.type == pgpSignedMessageBlock) return _Input(BytesSource(bytes), sniff.type, bytes.length, null);
    return _Input(ArmorReader.open(PgpReader.bytes(bytes)), sniff.type, bytes.length, null);
  }
  final (:length, :head) = pgpFileHead(data.path!);
  final sniff = sniffArmor(head);
  final source = FileSource(data.path!, onRead: onRead);
  if (sniff.type == null || sniff.type == pgpSignedMessageBlock) return _Input(source, sniff.type, length, source);
  return _Input(ArmorReader.open(PgpReader(source)), sniff.type, length, source);
}

ByteSource _plain(PgpData data, {void Function(int read)? onRead, List<FileSource>? opened}) {
  if (data.bytes != null) return BytesSource(data.bytes!);
  final source = FileSource(data.path!, onRead: onRead);
  opened?.add(source);
  return source;
}

Future<T> _guard<T>(Future<T> Function() body) async {
  try {
    return await body();
  } on PgpException {
    rethrow;
  } on KeyFormatException catch (e) {
    throw pgpErrorOf(e);
  } on Object catch (e) {
    final fileError = pgpFileError(e);
    if (fileError == null) rethrow;
    throw fileError;
  }
}

// ─── Keys ─────────────────────────────────────────────────────────────────────

/// A public key read for one use.
class PgpPublicKey {
  const PgpPublicKey(this.transferableKey, this.info);

  /// The binary transferable public key.
  final Uint8List transferableKey;
  final PgpKeyInfo info;

  String get fingerprintHex => info.primary.fingerprintHex;

  /// The first user ID, as given (`Name <email>`); empty when there is
  /// none.
  String get userId => info.userIds.firstOrNull ?? '';
}

/// Reads the first key of [input], pasted text (a `String`) or a file's
/// bytes, armored or binary. A secret key is reduced to its public part.
/// Throws [PgpProblem.notAMessage] for what is no key,
/// [PgpProblem.damaged] for a broken one, [PgpProblem.unsupported] naming
/// the kind for a key whose signatures this app cannot check (`nistp256`),
/// and [PgpProblem.keyUnusable] ([PgpKeyTrouble.invalid]) for a key whose
/// self-signatures do not verify.
Future<PgpPublicKey> readPgpPublicKey(Object input) => _guard(() async {
  final bytes = switch (input) {
    String() => Uint8List.fromList(utf8.encode(input)),
    List<int>() => Uint8List.fromList(input),
    _ => throw ArgumentError.value(input, 'input', 'must be a String or a List<int>'),
  };
  if (bytes.length > maxKeyInputLength) throw const PgpException(PgpProblem.tooLarge);
  final sniff = sniffArmor(bytes);
  final Uint8List binary;
  if (sniff.type == null) {
    binary = bytes;
  } else {
    if (sniff.type != pgpPublicKeyBlock && sniff.type != pgpPrivateKeyBlock) throw const PgpException(PgpProblem.notAMessage);
    binary = readArmorBlock(bytes, max: maxKeyInputLength);
  }
  if (binary.isEmpty || binary[0] & 0x80 == 0) throw const PgpException(PgpProblem.notAMessage);
  final PgpTransferableKey key;
  try {
    key = readTransferableKey(binary);
  } on KeyFormatException catch (e) {
    // What does not start as a key packet is not a key at all
    final tag = binary[0] & 0x40 == 0 ? (binary[0] >> 2) & 0x0f : binary[0] & 0x3f;
    if (tag != PgpTag.publicKey && tag != PgpTag.secretKey) throw const PgpException(PgpProblem.notAMessage);
    throw pgpErrorOf(e);
  }
  final public = transferablePublicKey(key.packets);
  final certificate = await PgpCertificate.read(public);
  final kind = certificate.unsupportedKind;
  if (kind != null) throw PgpException(PgpProblem.unsupported, detail: kind, fingerprint: certificate.fingerprintHex);
  if (!certificate.valid) {
    throw PgpException(PgpProblem.keyUnusable, reason: PgpKeyTrouble.invalid, fingerprint: certificate.fingerprintHex);
  }
  return PgpPublicKey(public, certificate.info);
});

/// Why the key of [transferableKey] may not be encrypted to at [now], or
/// null when it may: the same rules [encrypt] applies. With [toSign],
/// whether it may sign.
Future<PgpException?> pgpKeyTrouble(Uint8List transferableKey, DateTime now, {bool toSign = false}) async {
  try {
    final certificate = await PgpCertificate.read(transferableKey);
    toSign ? certificate.signingKey(now) : certificate.encryptionKey(now);
    return null;
  } on PgpException catch (e) {
    return e;
  }
}

/// [transferableKey], a binary transferable secret key, with every secret
/// that [passphrase] protects in it opened: a key a job can then sign and
/// decrypt with without a passphrase. Only ever kept in memory, for the
/// mail provider, until the vault locks (openspec: add-pgp-mail-provider,
/// decision 13). Throws [PgpProblem.wrongPassphrase] when [passphrase] is
/// not the key's, and [PgpProblem.notAMessage] for what is no secret key.
Future<Uint8List> openPgpSecretKey(Uint8List transferableKey, String passphrase) => _guard(() async {
  final key = readTransferableKey(transferableKey);
  if (key.packets.first.tag != PgpTag.secretKey) throw const PgpException(PgpProblem.notAMessage);
  return openedTransferableKey(key.packets, passphrase);
});

Future<MessageSigner> _signer(PgpSecretKey key, DateTime now) async {
  final certificate = await PgpCertificate.read(key.transferableKey);
  final packet = certificate.signingKey(now);
  try {
    return MessageSigner(packet, await secretOf(packet, passphrase: key.passphrase, elsewhere: key.elsewhere));
  } on PgpException catch (e) {
    throw PgpException(e.problem, detail: e.detail, reason: e.reason, fingerprint: certificate.fingerprintHex);
  }
}

Future<List<PgpCertificate>> _certificates(List<Uint8List> keys) async {
  final out = <PgpCertificate>[];
  for (final key in keys) {
    try {
      // Its self-signatures are checked when a signature names it
      out.add(await PgpCertificate.read(key, checkSelfSignatures: false));
    } on PgpException {
      // A key that cannot be read verifies nothing
      continue;
    }
  }
  return out;
}

// ─── Looking at a message ─────────────────────────────────────────────────────

/// What an input is.
enum PgpMessageKind {
  encrypted,

  /// A signed message that is not encrypted.
  signed,
  cleartextSigned,

  /// Signature packets alone: the file they sign is elsewhere.
  detachedSignature,

  /// Literal data with neither encryption nor a signature.
  plain,
  publicKey,
  secretKey,
}

/// What a message is, to whom, and how it is protected, read without any
/// secret.
class PgpMessageInfo {
  const PgpMessageInfo(
    this.kind, {
    this.recipientKeyIds = const [],
    this.hiddenRecipients = 0,
    this.passphrase = false,
    this.cipher,
    this.mode,
    this.form,
    this.noIntegrity = false,
    this.unsupported,
  });

  final PgpMessageKind kind;

  /// The key IDs an encrypted message names, in upper-case hexadecimal.
  final List<String> recipientKeyIds;

  /// How many recipients it hides: every key has to be tried for those.
  final int hiddenRecipients;

  /// Whether a passphrase can open it.
  final bool passphrase;

  /// The cipher's name, when the message says it on the outside (the AEAD
  /// forms, and a message with a passphrase alone): `AES-256`.
  final String? cipher;

  /// The AEAD mode's name: `OCB`.
  final String? mode;
  final EncryptedForm? form;

  /// The old form with nothing against tampering: refused.
  final bool noIntegrity;

  /// The usual name of what this app does not read in it, when the
  /// outside already shows it.
  final String? unsupported;
}

/// Reads the outside of [data]. Throws [PgpProblem.notAMessage] for what
/// is not OpenPGP data, and [PgpProblem.unsupported] for one part of a
/// multi-part armored message.
PgpMessageInfo inspectMessage(PgpData data) {
  final input = _open(data);
  try {
    switch (input.armorType) {
      case pgpSignedMessageBlock:
        return const PgpMessageInfo(PgpMessageKind.cleartextSigned);
      case pgpSignatureBlock:
        return const PgpMessageInfo(PgpMessageKind.detachedSignature);
      case pgpPublicKeyBlock:
        return const PgpMessageInfo(PgpMessageKind.publicKey);
      case pgpPrivateKeyBlock:
        return const PgpMessageInfo(PgpMessageKind.secretKey);
    }
    // Keys and lone signatures in binary show in their first packet
    final reader = PgpReader(input.source);
    final first = reader.peek();
    if (first != null && first & 0x80 != 0) {
      final tag = first & 0x40 == 0 ? (first >> 2) & 0x0f : first & 0x3f;
      if (tag == PgpTag.publicKey) return const PgpMessageInfo(PgpMessageKind.publicKey);
      if (tag == PgpTag.secretKey) return const PgpMessageInfo(PgpMessageKind.secretKey);
      if (tag == PgpTag.signature && input.length <= pgpPieceSize) {
        final packets = PacketReader(reader);
        var onlySignatures = true;
        try {
          for (var p = packets.next(); p != null; p = packets.next()) {
            if (p.tag != PgpTag.signature) onlySignatures = false;
          }
        } on PgpException {
          onlySignatures = false;
        }
        if (onlySignatures) return const PgpMessageInfo(PgpMessageKind.detachedSignature);
        // A signature that leads a message
        return const PgpMessageInfo(PgpMessageKind.signed);
      }
    }
    final outline = outlineMessage(reader);
    if (!outline.encrypted) return PgpMessageInfo(outline.signed ? PgpMessageKind.signed : PgpMessageKind.plain);
    final onlyPassphrase = outline.pkesks.isEmpty && outline.skesks.isNotEmpty;
    final cipher = outline.cipher ?? (onlyPassphrase && outline.skesks.first.encrypted == null ? outline.skesks.first.cipher : null);
    return PgpMessageInfo(
      PgpMessageKind.encrypted,
      recipientKeyIds: [
        for (final pkesk in outline.pkesks)
          if (pkesk.keyIdHex != null) pkesk.keyIdHex!,
      ],
      hiddenRecipients: outline.pkesks.where((p) => p.hidden).length,
      passphrase: outline.skesks.isNotEmpty,
      cipher: cipher == null ? null : cipherName(cipher),
      mode: outline.aead == null ? null : aeadName(outline.aead!),
      form: outline.form,
      noIntegrity: outline.noIntegrity,
      unsupported: outline.unsupported,
    );
  } finally {
    input.close();
  }
}

// ─── Encrypting ───────────────────────────────────────────────────────────────

/// Encrypts [data] to [recipients], binary transferable public keys, or,
/// when there are none, with [passphrase]; signed by [signer] inside the
/// encryption when given.
///
/// With [text] the data is a typed message: literal data of format `u`
/// with definite lengths, and the result is ASCII-armored. Without it the
/// data is a file named [fileName], and the result is binary, in partial
/// lengths. The result goes to [outputPath] when given, else it is
/// returned.
///
/// Throws [PgpProblem.keyUnusable] or [PgpProblem.unsupported], with the
/// key's fingerprint, for a recipient or signer that may not be used at
/// [now]: nothing is written then.
Future<Uint8List?> encrypt({
  required PgpData data,
  List<Uint8List> recipients = const [],
  String? passphrase,
  PgpSecretKey? signer,
  required bool text,
  String fileName = '',
  String? outputPath,
  DateTime? now,
  MessageRandom? random,
  void Function(int read)? onRead,
}) => _guard(() async {
  final time = now ?? DateTime.now();
  final certificates = [for (final recipient in recipients) await PgpCertificate.read(recipient)];
  final keys = [for (final certificate in certificates) certificate.encryptionKey(time)];
  // Version 6 session keys and SEIPD version 2 when every key reads them
  final aead = writesSeipd2(certificates);
  if (keys.isEmpty && (passphrase == null || passphrase.isEmpty)) {
    throw const PgpException(PgpProblem.keyUnusable, reason: PgpKeyTrouble.noSuchKey);
  }
  final messageSigner = signer == null ? null : await _signer(signer, time);
  final opened = <FileSource>[];
  final memory = text || outputPath == null ? BytesSink() : null;
  final file = memory == null ? FileSink(outputPath!) : null;
  try {
    await writeEncryptedMessage(
      data: _plain(data, onRead: onRead, opened: opened),
      out: memory ?? file!,
      recipients: keys,
      passphrase: keys.isEmpty ? passphrase : null,
      signer: messageSigner,
      format: text ? 0x75 : 0x62,
      fileName: text ? '' : fileName,
      definite: text,
      random: random ?? MessageRandom.secure(keys),
      time: time,
      aead: aead,
    );
    file?.close();
  } on Object {
    try {
      file?.close();
    } on PgpException {
      // The first error is the one to report
    }
    if (outputPath != null) _delete(outputPath);
    rethrow;
  } finally {
    for (final source in opened) {
      source.close();
    }
  }
  if (memory == null) return null;
  final bytes = memory.takeBytes();
  // A message ending in SEIPD version 2 is armored without the CRC-24 line
  final result = text ? Uint8List.fromList(latin1.encode(writeArmor(pgpMessageBlock, bytes, checksum: !aead))) : bytes;
  if (outputPath == null) return result;
  pgpWriteFile(outputPath, result);
  return null;
});

void _delete(String path) => pgpDeleteFile(path);

// ─── Decrypting ───────────────────────────────────────────────────────────────

/// A message that was decrypted, or read when it was only signed.
class PgpDecrypted {
  const PgpDecrypted({
    this.bytes,
    this.path,
    required this.length,
    required this.fileName,
    required this.isText,
    required this.encrypted,
    this.openedWithFingerprint,
    this.openedWithAlgorithm,
    this.openedWithPassphrase = false,
    this.cipher,
    this.mode,
    this.form,
    required this.signatures,
  });

  /// The content, when it fits in memory ([decrypt]'s `maxInMemory`).
  final Uint8List? bytes;

  /// Else the file it was written to, in the directory given.
  final String? path;
  final int length;

  /// The name the message carries for its content, cleaned to a base name
  /// with [cleanFileName]; empty when it has none.
  final String fileName;

  /// Whether the sender marked the content as text (format `t` or `u`).
  final bool isText;
  final bool encrypted;

  /// The primary key fingerprint of the key that opened it, in upper-case
  /// hexadecimal, and GnuPG's name for the subkey it was encrypted to
  /// (`cv25519`, `rsa3072`).
  final String? openedWithFingerprint;
  final String? openedWithAlgorithm;
  final bool openedWithPassphrase;

  /// `AES-256`, and for the AEAD forms `OCB`, `GCM` or `EAX`.
  final String? cipher;
  final String? mode;
  final EncryptedForm? form;

  /// One result per signature inside; empty when it is not signed.
  final List<SignatureResult> signatures;
}

/// A file name the sender gave, reduced to a base name without path
/// separators or control characters, so that it can name a file here.
/// When nothing is left, [inputName] without `.gpg`, `.pgp` or `.asc`;
/// when that is empty too, `decrypted`.
String cleanFileName(String name, {String? inputName}) {
  String clean(String s) {
    final base = s.split(RegExp(r'[/\\]')).last;
    final kept = base.replaceAll(RegExp(r'[\x00-\x1f\x7f:*?"<>|]'), '').trim();
    return kept == '.' || kept == '..' ? '' : kept;
  }

  // GnuPG names data from a pipe "_CONSOLE"
  final given = name == '_CONSOLE' ? '' : clean(name);
  if (given.isNotEmpty) return given;
  final fallback = clean(inputName ?? '').replaceFirst(RegExp(r'\.(gpg|pgp|asc)$', caseSensitive: false), '');
  return fallback.isEmpty ? 'decrypted' : fallback;
}

/// Collects output in memory up to a bound, then moves it to a file.
class _SpillSink implements ByteSink {
  _SpillSink(this._maxInMemory, this._path);

  final int _maxInMemory;
  final String? _path;
  BytesSink? _memory = BytesSink();
  FileSink? file;
  int length = 0;

  @override
  void add(Uint8List data) {
    length += data.length;
    final memory = _memory;
    if (memory != null) {
      if (memory.length + data.length <= _maxInMemory) {
        memory.add(data);
        return;
      }
      final path = _path;
      if (path == null) throw const PgpException(PgpProblem.tooLarge);
      file = FileSink(path)..add(memory.takeBytes());
      _memory = null;
    }
    file!.add(data);
  }

  Uint8List? takeBytes() => _memory?.takeBytes();
}

/// Decrypts the message in [data], armored or binary, with whichever of
/// [keys] it is encrypted to, else with [passphrase]; a message that is
/// only signed is read as well. Signatures inside are checked against
/// [verifiers], binary transferable public keys, at [now].
///
/// Content of up to [maxInMemory] bytes is returned in memory; more goes
/// to a file in [outputDirectory], named by [cleanFileName], and without
/// a directory is [PgpProblem.tooLarge]. Nothing is returned, and the
/// partial file is deleted, unless the message's integrity check passed
/// over all of it.
///
/// Throws [PgpProblem.passphraseNeeded] with the fingerprint of a key of
/// [keys] that could open it and is locked, or with none when the message
/// itself takes a passphrase; [PgpProblem.noKeyOpensIt] with the key IDs
/// it names; [PgpProblem.unsupported] with a name; [PgpProblem.noIntegrity].
Future<PgpDecrypted> decrypt({
  required PgpData data,
  List<PgpSecretKey> keys = const [],
  String? passphrase,
  List<Uint8List> verifiers = const [],
  String? outputDirectory,
  String? inputName,
  int maxInMemory = maxPgpTextLength,
  DateTime? now,
  void Function(int read)? onRead,
}) => _guard(() async {
  final input = _open(data, onRead: onRead);
  final partPath = outputDirectory == null ? null : pgpJoinPath(outputDirectory, 'decrypting.part');
  final sink = _SpillSink(maxInMemory, partPath);
  try {
    if (input.armorType == pgpSignedMessageBlock) {
      final verified = await _verifyCleartext(input, await _certificates(verifiers), now ?? DateTime.now());
      return PgpDecrypted(
        bytes: verified.content,
        length: verified.content!.length,
        fileName: '',
        isText: true,
        encrypted: false,
        signatures: verified.signatures,
      );
    }
    if (input.armorType != null && input.armorType != pgpMessageBlock) throw const PgpException(PgpProblem.notAMessage);
    final access = <SecretKeyAccess>[];
    for (final key in keys) {
      try {
        // To decrypt, a key's standing and self-signatures do not matter
        access.add(
          SecretKeyAccess(
            await PgpCertificate.read(key.transferableKey, checkSelfSignatures: false),
            passphrase: key.passphrase,
            elsewhere: key.elsewhere,
          ),
        );
      } on PgpException {
        continue;
      }
    }
    final read = await readMessage(
      input.source,
      output: sink,
      keys: access,
      passphrase: passphrase,
      verifiers: await _certificates(verifiers),
      inputLength: input.length,
      now: now ?? DateTime.now(),
    );
    if (read.format == 0) throw const PgpException(PgpProblem.notAMessage, detail: 'no content');
    final name = cleanFileName(read.fileName, inputName: inputName);
    String? path;
    final file = sink.file;
    if (file != null) {
      file.close();
      path = pgpJoinPath(outputDirectory!, name);
      pgpRenameFile(partPath!, path);
    }
    final opened = read.openedWith;
    return PgpDecrypted(
      bytes: sink.takeBytes(),
      path: path,
      length: sink.length,
      // Without a name of its own it is only "decrypted" when it is a file
      fileName: read.fileName.isEmpty && inputName == null ? '' : name,
      isText: read.format == 0x74 || read.format == 0x75,
      encrypted: opened != null,
      openedWithFingerprint: opened?.certificate?.fingerprintHex,
      openedWithAlgorithm: opened?.key?.name,
      openedWithPassphrase: opened?.passphrase ?? false,
      cipher: read.cipher == null ? null : cipherName(read.cipher!),
      mode: read.aead == null ? null : aeadName(read.aead!),
      form: read.form,
      signatures: read.signatures,
    );
  } on Object {
    try {
      sink.file?.close();
    } on PgpException {
      // The first error is the one to report
    }
    if (partPath != null) _delete(partPath);
    rethrow;
  } finally {
    input.close();
  }
});

// ─── Signing ──────────────────────────────────────────────────────────────────

/// The form a signature is written in.
enum PgpSignatureForm {
  /// The text, readable, with its signature in armor after it.
  cleartext,

  /// The signature alone, binary: the `.sig` file beside a file.
  detached,

  /// The signature alone, armored.
  detachedArmored,
}

/// Signs [data] with [signer]. [PgpSignatureForm.cleartext] takes UTF-8
/// text of up to [maxPgpTextLength] and returns the clear-signed text;
/// the detached forms take any data and return the signature, leaving the
/// data untouched.
Future<Uint8List> sign({required PgpData data, required PgpSecretKey signer, required PgpSignatureForm form, DateTime? now}) =>
    _guard(() async {
      final time = now ?? DateTime.now();
      final messageSigner = await _signer(signer, time);
      final opened = <FileSource>[];
      try {
        if (form == PgpSignatureForm.cleartext) {
          final bytes = PgpReader(_plain(data, opened: opened)).rest(max: maxPgpTextLength);
          final text = utf8.decode(bytes, allowMalformed: true);
          final signature = await writeDetachedSignature(
            data: BytesSource(cleartextSignedBytes(Uint8List.fromList(utf8.encode(text.replaceAll('\r\n', '\n'))))),
            signer: messageSigner,
            text: true,
            time: time,
          );
          return Uint8List.fromList(utf8.encode(writeCleartext(text, signature, version6: messageSigner.key.version == 6)));
        }
        final signature = await writeDetachedSignature(
          data: _plain(data, opened: opened),
          signer: messageSigner,
          time: time,
        );
        if (form == PgpSignatureForm.detached) return signature;
        // A version 6 signature is armored without the CRC-24 line
        return Uint8List.fromList(latin1.encode(writeArmor(pgpSignatureBlock, signature, checksum: messageSigner.key.version != 6)));
      } finally {
        for (final source in opened) {
          source.close();
        }
      }
    });

// ─── Verifying ────────────────────────────────────────────────────────────────

/// What verifying came to.
class PgpVerified {
  const PgpVerified(this.signatures, {this.content, this.isText = false});

  /// One result per signature.
  final List<SignatureResult> signatures;

  /// The signed content of a clear-signed text or of a signed message;
  /// null for a detached signature.
  final Uint8List? content;
  final bool isText;
}

Future<PgpVerified> _verifyCleartext(_Input input, List<PgpCertificate> verifiers, DateTime now) async {
  final message = readCleartext(PgpReader(input.source).rest(max: maxCleartextLength));
  final results = await checkDetachedSignatures(
    data: BytesSource(cleartextSignedBytes(message.textBytes)),
    signatures: message.signatures,
    verifiers: verifiers,
    now: now,
  );
  return PgpVerified(results, content: message.textBytes, isText: true);
}

/// Checks signatures against [verifiers], binary transferable public
/// keys, at [now].
///
/// With [data], [signed] is its detached signature, armored or binary.
/// Without it, [signed] is a clear-signed text or a signed message, and
/// its content is returned with the results (up to [maxInMemory] bytes).
///
/// Throws [PgpProblem.notAMessage] for what holds no signature: with the
/// detail `encrypted` for an encrypted message, which is for [decrypt],
/// and `detached` for a lone signature given without its data.
Future<PgpVerified> verify({
  required PgpData signed,
  PgpData? data,
  List<Uint8List> verifiers = const [],
  int maxInMemory = maxPgpTextLength,
  DateTime? now,
  void Function(int read)? onRead,
}) => _guard(() async {
  final time = now ?? DateTime.now();
  final certificates = await _certificates(verifiers);
  final input = _open(signed, onRead: data == null ? onRead : null);
  final opened = <FileSource>[];
  try {
    if (data != null) {
      if (input.armorType != null && input.armorType != pgpSignatureBlock) {
        throw const PgpException(PgpProblem.notAMessage, detail: 'not a signature');
      }
      final signatures = PgpReader(input.source).rest(max: maxKeyInputLength);
      final results = await checkDetachedSignatures(
        data: _plain(data, onRead: onRead, opened: opened),
        signatures: signatures,
        verifiers: certificates,
        now: time,
      );
      return PgpVerified(results);
    }
    switch (input.armorType) {
      case pgpSignedMessageBlock:
        return await _verifyCleartext(input, certificates, time);
      case pgpSignatureBlock:
        throw const PgpException(PgpProblem.notAMessage, detail: 'detached');
      case null || pgpMessageBlock:
        break;
      default:
        throw const PgpException(PgpProblem.notAMessage);
    }
    final sink = _SpillSink(maxInMemory, null);
    final MessageRead read;
    try {
      read = await readMessage(input.source, output: sink, verifiers: certificates, inputLength: input.length, now: time);
    } on PgpException catch (e) {
      if (e.problem == PgpProblem.noKeyOpensIt || e.problem == PgpProblem.passphraseNeeded || e.problem == PgpProblem.noIntegrity) {
        throw const PgpException(PgpProblem.notAMessage, detail: 'encrypted');
      }
      rethrow;
    }
    if (read.format == 0) throw PgpException(PgpProblem.notAMessage, detail: read.signatures.isEmpty ? null : 'detached');
    if (read.signatures.isEmpty) throw const PgpException(PgpProblem.notAMessage, detail: 'not signed');
    return PgpVerified(read.signatures, content: sink.takeBytes(), isText: read.format == 0x74 || read.format == 0x75);
  } finally {
    input.close();
    for (final source in opened) {
      source.close();
    }
  }
});

/// The usual name of the hash a weak signature was made with, for the
/// sentence that says so.
String pgpHashName(int id) => hashName(id);

/// The `micalg` parameter of a PGP/MIME signed mail (RFC 3156, section 5)
/// for [signature], a detached signature, armored or binary:
/// `pgp-sha512`. Throws [PgpProblem.notAMessage] for what holds no
/// signature.
String pgpMicalg(Uint8List signature) {
  try {
    final binary = sniffArmor(signature).type == null ? signature : readArmorBlock(signature, max: maxKeyInputLength);
    final packet = readPackets(binary).firstWhere((p) => p.tag == PgpTag.signature);
    return 'pgp-${hashName(packet.body[3]).toLowerCase().replaceAll('-', '')}';
  } on StateError {
    throw const PgpException(PgpProblem.notAMessage);
  } on RangeError {
    throw const PgpException(PgpProblem.notAMessage);
  } on KeyFormatException {
    throw const PgpException(PgpProblem.notAMessage);
  } on PgpException {
    throw const PgpException(PgpProblem.notAMessage);
  }
}

/// [transferableKey], a binary transferable public key, as an armored
/// `PGP PUBLIC KEY BLOCK`.
String armoredPgpPublicKey(Uint8List transferableKey) => writeArmor(pgpPublicKeyBlock, transferableKey);
