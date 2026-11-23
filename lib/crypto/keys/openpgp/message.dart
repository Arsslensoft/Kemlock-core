// OpenPGP messages (RFC 9580 section 10.3): reading a message's packet
// sequence into what it is (encrypted to whom, signed by whom, the
// literal data), and writing one.
//
// Reading stacks sources: packets (partial lengths joined), decryption,
// decompression, packets again, literal data, with every signature's hash
// fed as the literal data passes. The literal data goes to the caller's
// sink as it is read, and the integrity check of SEIPD version 1 comes at
// the very end: the caller must hold the sink's content back until
// [readMessage] returns, and throw it away when it throws.
//
// Two forms are written (design decision 3 of add-post-quantum-pgp): the
// one every OpenPGP program reads, PKESK version 3 or SKESK version 4, then
// SEIPD version 1 with AES-256; and, when every recipient's key says it
// reads it, PKESK version 6 and SEIPD version 2 with AES-256 in OCB. Each
// holds a one-pass signature, the literal data and the signature,
// uncompressed.

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

import '../../bytes.dart';
import 'data_signature.dart';
import 'inflate.dart';
import 'key_info.dart';
import 'modes.dart';
import 'packets.dart';
import 'pgp_error.dart';
import 'pgp_files.dart';
import 's2k.dart';
import 'secret_key.dart';
import 'session_key.dart';
import 'stream.dart';
import 'usable_keys.dart';
import 'writer.dart' show defaultS2kCount;

// ─── Reading ──────────────────────────────────────────────────────────────────

/// A key that may open a message: a transferable secret key, and the
/// passphrase of its secret parts when the person gave one.
class SecretKeyAccess {
  const SecretKeyAccess(this.certificate, {this.passphrase, this.elsewhere});

  final PgpCertificate certificate;
  final String? passphrase;

  /// The private step of the key's parts on a card, when it has some.
  final DelegatedSecret? elsewhere;
}

/// What was used to open an encrypted message.
class OpenedWith {
  const OpenedWith.key(PgpCertificate this.certificate, KeyPacket this.key) : passphrase = false;

  const OpenedWith.passphrase() : certificate = null, key = null, passphrase = true;

  /// The key it was encrypted to, and the certificate it belongs to.
  final PgpCertificate? certificate;
  final KeyPacket? key;

  /// Whether a passphrase opened it, with no key.
  final bool passphrase;
}

/// How a message's data was protected.
enum EncryptedForm {
  /// SEIPD version 1: CFB with a SHA-1 check at the end.
  seipd1,

  /// SEIPD version 2: AEAD in chunks.
  seipd2,

  /// GnuPG's OCB packet.
  ocbPacket,
}

/// A message that was read.
class MessageRead {
  MessageRead._();

  /// Null for a message that was not encrypted.
  OpenedWith? openedWith;
  EncryptedForm? form;

  /// The cipher and, in the AEAD forms, the mode.
  int? cipher;
  int? aead;

  /// `b`, `t` or `u`, as a code unit; 0 when the message had no literal
  /// data.
  int format = 0;

  /// The name the literal data carries, as given: it is the sender's, and
  /// must be cleaned before it names a file.
  String fileName = '';

  bool compressed = false;

  /// One result per signature, in the order of the signature packets.
  List<SignatureResult> signatures = const [];
}

/// The most a compressed message may unpack to: 64 MB and a hundred times
/// its own size.
int maxUnpackedSize(int messageSize) => 64 * 1024 * 1024 + 100 * messageSize;

/// The most BZip2 data read: `archive` decodes it from one buffer.
const maxBzip2Input = 64 * 1024 * 1024;

/// The most BZip2 data unpacked. `archive` unpacks it into memory whole,
/// before any bound of the caller's sees a byte, so the bound of the other
/// kinds, which grows with the message, would let a few megabytes of zeros
/// ask for a gigabyte and end the app. ZIP and ZLIB are read a piece at a time.
const maxBzip2Output = 64 * 1024 * 1024;

const _maxSmallPacket = 1 << 20;

/// Reads the message in [input], binary packets, writing its literal data
/// to [output] as it goes. [keys] are tried for the session key, then
/// [passphrase]; signatures are checked against [verifiers] at [now].
/// [inputLength] is the message's size, which bounds what a compressed
/// message may unpack to.
///
/// Throws a [PgpException] and nothing else. On any throw, what [output]
/// was given must be discarded: it was not yet known to be whole.
Future<MessageRead> readMessage(
  ByteSource input, {
  required ByteSink output,
  List<SecretKeyAccess> keys = const [],
  String? passphrase,
  List<PgpCertificate> verifiers = const [],
  required int inputLength,
  required DateTime now,
}) async {
  try {
    return await _readMessage(
      input,
      output: output,
      keys: keys,
      passphrase: passphrase,
      verifiers: verifiers,
      inputLength: inputLength,
      now: now,
    );
  } on PgpException {
    rethrow;
  } on Object catch (e) {
    final fileError = pgpFileError(e);
    if (fileError != null) throw fileError;
    // Anything else is a reader tripping over bytes it did not expect
    throw PgpException(PgpProblem.damaged, detail: '$e');
  }
}

Future<MessageRead> _readMessage(
  ByteSource input, {
  required ByteSink output,
  required List<SecretKeyAccess> keys,
  required String? passphrase,
  required List<PgpCertificate> verifiers,
  required int inputLength,
  required DateTime now,
}) async {
  final packets = PacketReader(PgpReader(input));
  final pkesks = <Pkesk>[];
  final skesks = <Skesk>[];
  PacketIn? packet;
  try {
    for (packet = packets.next(); packet != null; packet = packets.next()) {
      if (packet.tag == PgpTag.pkesk) {
        pkesks.add(parsePkesk(packet.body.rest(max: _maxSmallPacket)));
      } else if (packet.tag == PgpTag.skesk) {
        skesks.add(parseSkesk(packet.body.rest(max: _maxSmallPacket)));
      } else if (packet.tag != PgpTag.marker) {
        break;
      }
    }
  } on PgpException catch (e) {
    // Bytes that do not even start as packets are no message at all
    if (e.problem == PgpProblem.damaged && pkesks.isEmpty && skesks.isEmpty) throw const PgpException(PgpProblem.notAMessage);
    rethrow;
  }
  if (packet == null) throw PgpException(pkesks.isEmpty && skesks.isEmpty ? PgpProblem.notAMessage : PgpProblem.damaged);

  final result = MessageRead._();
  final inner = _Inner(result, output, maxUnpackedSize(inputLength));
  switch (packet.tag) {
    case PgpTag.encryptedData:
      throw const PgpException(PgpProblem.noIntegrity);
    case PgpTag.seipd || PgpTag.ocbEncryptedData:
      final (session, opened) = await _sessionKey(pkesks, skesks, keys, passphrase);
      result.openedWith = opened;
      final version = packet.body.byte();
      final ByteSource plain;
      // A passphrase whose key is the session key shows it is wrong only
      // in the data
      var unproven = false;
      if (packet.tag == PgpTag.seipd && version == 1) {
        final cipher = session.cipher;
        pgpCheck(cipher != null && cipherKeyLength(cipher) == session.key.length, 'session key');
        unproven = opened.passphrase && skesks.every((s) => s.version == 4 && s.encrypted == null);
        result
          ..form = EncryptedForm.seipd1
          ..cipher = cipher;
        plain = Seipd1Reader(session.key, packet.body, wrongKeyIs: unproven ? PgpProblem.wrongPassphrase : PgpProblem.damaged);
      } else if (packet.tag == PgpTag.seipd && version == 2) {
        final head = packet.body;
        // The cipher and mode are the packet's first two octets
        final peeked = _Peeked(head, 2);
        result
          ..form = EncryptedForm.seipd2
          ..cipher = peeked.bytes[0]
          ..aead = peeked.bytes[1];
        plain = AeadChunkReader.seipd2(PgpReader(peeked), session.key);
      } else if (packet.tag == PgpTag.ocbEncryptedData && version == 1) {
        final peeked = _Peeked(packet.body, 2);
        result
          ..form = EncryptedForm.ocbPacket
          ..cipher = peeked.bytes[0]
          ..aead = peeked.bytes[1];
        plain = AeadChunkReader.ocbPacket(PgpReader(peeked), session.key);
      } else {
        throw PgpException(PgpProblem.unsupported, detail: 'encrypted data version $version');
      }
      try {
        inner.readPackets(PacketReader(PgpReader(plain)), depth: 0);
      } on PgpException catch (e) {
        if (unproven && e.problem == PgpProblem.damaged) throw const PgpException(PgpProblem.wrongPassphrase);
        rethrow;
      }
    case PgpTag.compressedData || PgpTag.onePassSignature || PgpTag.signature || PgpTag.literalData:
      pgpCheck(pkesks.isEmpty && skesks.isEmpty, 'session keys with no encrypted data');
      inner.readPackets(packets, first: packet, depth: 0);
    case PgpTag.publicKey || PgpTag.secretKey:
      throw const PgpException(PgpProblem.notAMessage, detail: 'a key');
    default:
      throw PgpException(pkesks.isEmpty && skesks.isEmpty ? PgpProblem.notAMessage : PgpProblem.damaged, detail: 'packet ${packet.tag}');
  }
  result.signatures = [for (final pending in inner.signatures) await pending.check(verifiers, now)];
  return result;
}

/// A source with its first [count] bytes read ahead and still given out.
class _Peeked implements ByteSource {
  _Peeked(this._in, int count) : bytes = _in.bytes(count);

  final PgpReader _in;
  final Uint8List bytes;
  bool _given = false;

  @override
  Uint8List? next() {
    if (!_given) {
      _given = true;
      return bytes;
    }
    return _in.some();
  }
}

/// Finds the session key: each key packet a PKESK may be for is unlocked
/// and tried, then the passphrase on each SKESK. A vault key that could
/// open the message but is locked is asked for before any passphrase of
/// the message.
Future<(SessionKey, OpenedWith)> _sessionKey(List<Pkesk> pkesks, List<Skesk> skesks, List<SecretKeyAccess> keys, String? passphrase) async {
  PgpException? locked;
  PgpException? named;
  PgpException? broken;
  PgpException? other;
  // [aboutKey] says the trouble is with the key itself (locked, or of a kind
  // not used), which is then named; a session key that names a cipher this
  // app does not read is the trouble of the message, whoever opened it
  void remember(PgpException e, SecretKeyAccess access, {required bool aboutKey}) {
    final about = PgpException(
      e.problem,
      detail: e.detail,
      reason: e.reason,
      fingerprint: aboutKey ? access.certificate.fingerprintHex : null,
    );
    switch (e.problem) {
      case PgpProblem.passphraseNeeded || PgpProblem.wrongPassphrase:
        locked ??= about;
      case PgpProblem.unsupported:
        named ??= about;
      case PgpProblem.noSecretHere:
        other ??= about;
      case PgpProblem.damaged:
        // The key the message names did not open its own session key
        broken ??= about;
      default:
        break;
    }
  }

  // Keys whose secret is here first: a card is asked for only when none of them opens it
  for (final elsewhere in [false, true]) {
    for (final pkesk in pkesks) {
      for (final access in keys) {
        for (final key in access.certificate.decryptionKeys(pkesk)) {
          final onCard = access.elsewhere != null && isCardStub(key);
          if (onCard != elsewhere) continue;
          // A hidden recipient is not worth bringing a card out for
          if (onCard && pkesk.hidden) continue;
          final PgpSecret secret;
          try {
            secret = await secretOf(key, passphrase: access.passphrase, elsewhere: access.elsewhere);
          } on PgpException catch (e) {
            // A hidden recipient may be anybody: a locked key is asked for
            // only when the message names it
            if (!pkesk.hidden || e.problem == PgpProblem.unsupported) remember(e, access, aboutKey: true);
            continue;
          }
          try {
            return (await openPkesk(pkesk, key, secret), OpenedWith.key(access.certificate, key));
          } on PgpException catch (e) {
            // The person gave up on the card: nothing more is tried
            if (e.problem == PgpProblem.cancelled) rethrow;
            if (!pkesk.hidden) remember(e, access, aboutKey: false);
          }
        }
      }
    }
  }
  if (locked != null) throw locked!;
  if (skesks.isNotEmpty) {
    PgpException? failed;
    for (final skesk in skesks) {
      final name = skesk.unsupportedName;
      if (name != null) {
        failed ??= PgpException(PgpProblem.unsupported, detail: name);
        continue;
      }
      if (passphrase == null) throw const PgpException(PgpProblem.passphraseNeeded);
      try {
        return (openSkesk(skesk, utf8.encode(passphrase)), const OpenedWith.passphrase());
      } on PgpException catch (e) {
        if (e.problem == PgpProblem.wrongPassphrase || failed == null) failed = e;
      }
    }
    throw named ?? failed!;
  }
  if (named != null) throw named!;
  if (broken != null) throw broken!;
  if (other != null) throw other!;
  pgpCheck(pkesks.isNotEmpty, 'encrypted data with no session key');
  throw PgpException(
    PgpProblem.noKeyOpensIt,
    keyIds: [
      for (final pkesk in pkesks)
        if (pkesk.keyIdHex != null) pkesk.keyIdHex!,
    ],
  );
}

/// What is inside the encryption, or the whole of a message that has
/// none: compressed data, one-pass signatures, literal data, signatures.
class _Inner {
  _Inner(this._result, this._output, this._maxUnpacked);

  final MessageRead _result;
  final ByteSink _output;
  final int _maxUnpacked;

  /// Every signature, in the order of the signature packets.
  final signatures = <PendingSignature>[];

  /// One-pass packets waiting for their signatures, which come in the
  /// opposite order after the data.
  final _onePass = <PendingSignature>[];

  /// Signatures that lead the message, hashed like the others.
  final _leading = <PendingSignature>[];
  bool _literalSeen = false;

  void readPackets(PacketReader reader, {PacketIn? first, required int depth}) {
    for (var packet = first ?? reader.next(); packet != null; packet = reader.next()) {
      final body = packet.body;
      switch (packet.tag) {
        case PgpTag.marker || PgpTag.padding:
          break;
        case PgpTag.compressedData:
          pgpCheck(depth < 2 && !_literalSeen, 'nested compression');
          _result.compressed = true;
          readPackets(PacketReader(PgpReader(_decompress(body.byte(), body))), depth: depth + 1);
        case PgpTag.onePassSignature:
          pgpCheck(!_literalSeen, 'one-pass signature after the data');
          final r = PgpReader.bytes(body.rest(max: _maxSmallPacket));
          final version = r.byte();
          pgpCheck(version == 3 || version == 6, 'one-pass signature version');
          final type = r.byte();
          final hashAlgorithm = r.byte();
          r.byte(); // the public-key algorithm: the signature says it too
          final salt = version == 6 ? r.bytes(r.byte()) : null;
          _onePass.add(PendingSignature.onePass(type: type, hashAlgorithm: hashAlgorithm, salt: salt));
        case PgpTag.signature:
          final signature = asPgpError(() => parseSignature(body.rest(max: _maxSmallPacket)));
          if (!_literalSeen) {
            final pending = PendingSignature.of(signature);
            _leading.add(pending);
            signatures.add(pending);
          } else if (_onePass.isNotEmpty) {
            signatures.add(_onePass.removeLast()..signature = signature);
          }
        // A signature after the data with nothing announcing it was not
        // hashed for, and cannot be checked: it is left out
        case PgpTag.literalData:
          pgpCheck(!_literalSeen, 'two literal data packets');
          _literalSeen = true;
          _result.format = body.byte();
          _result.fileName = utf8.decode(body.bytes(body.byte()), allowMalformed: true);
          body.bytes(4); // the date
          final hashers = [..._leading, ..._onePass];
          for (var piece = body.some(); piece != null; piece = body.some()) {
            _output.add(piece);
            for (final hasher in hashers) {
              hasher.add(piece);
            }
          }
        default:
          // Tags 40 to 63 may be skipped (RFC 9580 section 4.3); nothing
          // else belongs here
          pgpCheck(packet.tag >= 40, 'packet ${packet.tag} in a message');
      }
    }
    if (depth == 0) {
      // A one-pass packet whose signature never came
      signatures.addAll(_onePass.reversed);
      _onePass.clear();
    }
  }

  ByteSource _decompress(int algorithm, PgpReader body) => switch (algorithm) {
    0 => body,
    1 => _Bounded(StreamInflate(body, raw: true), _maxUnpacked),
    2 => _Bounded(StreamInflate(body, raw: false), _maxUnpacked),
    3 => _bzip2(body),
    _ => throw PgpException(PgpProblem.unsupported, detail: 'compression $algorithm'),
  };

  ByteSource _bzip2(PgpReader body) {
    final compressed = body.rest(max: maxBzip2Input);
    final out = OutputMemoryStream();
    bool ok;
    try {
      final most = _maxUnpacked < maxBzip2Output ? _maxUnpacked : maxBzip2Output;
      ok = BZip2Decoder().decodeStream(InputMemoryStream(compressed), out, verify: true, maxOutputSize: most);
    } on ArchiveException {
      // Thrown only for the bound: a malformed stream gives false
      throw const PgpException(PgpProblem.tooLarge);
    }
    pgpCheck(ok, 'BZip2');
    return BytesSource(out.getBytes());
  }
}

/// Stops a source that gives more than [_max] bytes, before the piece
/// that passes the bound is handed on.
class _Bounded implements ByteSource {
  _Bounded(this._in, this._max);

  final ByteSource _in;
  final int _max;
  int _given = 0;

  @override
  Uint8List? next() {
    final piece = _in.next();
    if (piece == null) return null;
    _given += piece.length;
    if (_given > _max) throw const PgpException(PgpProblem.tooLarge);
    return piece;
  }
}

// ─── Looking, without a secret ────────────────────────────────────────────────

/// What a message's outside says.
class MessageOutline {
  MessageOutline._();

  final pkesks = <Pkesk>[];
  final skesks = <Skesk>[];

  /// The tag of the packet after the session keys: 18, 20 or 9 for an
  /// encrypted message; 8, 4, 2 or 11 for one that is not.
  int tag = 0;

  /// For encrypted data that names them outside: the form, the cipher and
  /// the AEAD mode. SEIPD version 1 keeps its cipher with the session key.
  EncryptedForm? form;
  int? cipher;
  int? aead;

  /// For a message that is not encrypted: whether it is signed.
  bool signed = false;

  /// The name of what this app cannot read, when the outside already
  /// shows it (`Argon2`, `CAST5`, `AEAD chunks over 4 MiB`).
  String? unsupported;

  bool get encrypted => tag == PgpTag.seipd || tag == PgpTag.ocbEncryptedData || tag == PgpTag.encryptedData;

  /// Tag 9: encrypted with nothing against tampering.
  bool get noIntegrity => tag == PgpTag.encryptedData;
}

/// Reads the packets of [input] up to the encrypted data, or, for a
/// message that is not encrypted, far enough to see whether it is signed.
/// Throws [PgpProblem.notAMessage] for what is no message.
MessageOutline outlineMessage(ByteSource input) {
  final outline = MessageOutline._();
  try {
    final packets = PacketReader(PgpReader(input));
    PacketIn? packet;
    for (packet = packets.next(); packet != null; packet = packets.next()) {
      if (packet.tag == PgpTag.pkesk) {
        outline.pkesks.add(parsePkesk(packet.body.rest(max: _maxSmallPacket)));
      } else if (packet.tag == PgpTag.skesk) {
        outline.skesks.add(parseSkesk(packet.body.rest(max: _maxSmallPacket)));
      } else if (packet.tag != PgpTag.marker) {
        break;
      }
    }
    if (packet == null) throw const PgpException(PgpProblem.notAMessage);
    outline.tag = packet.tag;
    final body = packet.body;
    switch (packet.tag) {
      case PgpTag.seipd:
        final version = body.byte();
        if (version == 1) {
          outline.form = EncryptedForm.seipd1;
        } else if (version == 2) {
          outline
            ..form = EncryptedForm.seipd2
            ..cipher = body.byte()
            ..aead = body.byte();
          if (body.byte() > maxAeadChunkOctet) outline.unsupported = 'AEAD chunks over 4 MiB';
        } else {
          outline.unsupported = 'encrypted data version $version';
        }
      case PgpTag.ocbEncryptedData:
        final version = body.byte();
        outline
          ..form = EncryptedForm.ocbPacket
          ..cipher = body.byte()
          ..aead = body.byte();
        if (version != 1) outline.unsupported = 'encrypted data version $version';
        if (body.byte() > maxAeadChunkOctet) outline.unsupported = 'AEAD chunks over 4 MiB';
      case PgpTag.encryptedData:
        break;
      case PgpTag.onePassSignature || PgpTag.signature:
        outline.signed = true;
      case PgpTag.compressedData:
        // The first packet inside says whether it is signed
        final algorithm = body.byte();
        final ByteSource inside = switch (algorithm) {
          0 => body,
          1 => StreamInflate(body, raw: true),
          2 => StreamInflate(body, raw: false),
          // BZip2 is decoded whole: not for a look
          _ => BytesSource(Uint8List(0)),
        };
        final first = PacketReader(PgpReader(inside)).next()?.tag;
        outline.signed = first == PgpTag.onePassSignature || first == PgpTag.signature;
      case PgpTag.literalData:
        break;
      default:
        throw const PgpException(PgpProblem.notAMessage);
    }
    final cipher = outline.cipher;
    if (cipher != null && cipher != cipherAes128 && cipher != cipherAes192 && cipher != cipherAes256) {
      outline.unsupported ??= cipherName(cipher);
    }
    final aead = outline.aead;
    if (aead != null && aead != aeadEax && aead != aeadOcb && aead != aeadGcm) outline.unsupported ??= aeadName(aead);
    // A message only a passphrase could open, by a method this app lacks
    if (outline.encrypted &&
        outline.pkesks.isEmpty &&
        outline.skesks.isNotEmpty &&
        outline.skesks.every((s) => s.unsupportedName != null)) {
      outline.unsupported ??= outline.skesks.first.unsupportedName;
    }
    return outline;
  } on PgpException catch (e) {
    if (e.problem == PgpProblem.damaged && outline.tag == 0 && outline.pkesks.isEmpty && outline.skesks.isEmpty) {
      throw const PgpException(PgpProblem.notAMessage);
    }
    rethrow;
  } on Object catch (e) {
    throw PgpException(PgpProblem.damaged, detail: '$e');
  }
}

// ─── Writing ──────────────────────────────────────────────────────────────────

/// The random bytes one message takes, passed in so that tests can pin
/// what is written.
class MessageRandom {
  const MessageRandom({required this.sessionKey, required this.prefix, required this.salt, required this.perRecipient, this.aeadSalt});

  /// Fresh bytes from the platform's secure source for [recipients].
  factory MessageRandom.secure(List<KeyPacket> recipients) => MessageRandom(
    sessionKey: randomBytes(32),
    prefix: randomBytes(16),
    salt: randomBytes(8),
    perRecipient: [for (final recipient in recipients) randomBytes(pkeskRandomLength(recipient, 32))],
    aeadSalt: randomBytes(32),
  );

  /// The AES-256 session key of a message to people.
  final Uint8List sessionKey;

  /// The 16 bytes the encrypted data starts with.
  final Uint8List prefix;

  /// The S2K salt of a message with a passphrase.
  final Uint8List salt;

  /// For each recipient, what [pkeskRandomLength] asks for.
  final List<Uint8List> perRecipient;

  /// The 32-byte salt of a version 2 SEIPD packet; fresh bytes when null.
  final Uint8List? aeadSalt;
}

/// Who signs a message: the key packet [key] and its unlocked [secret].
class MessageSigner {
  const MessageSigner(this.key, this.secret);

  final KeyPacket key;
  final PgpSecret secret;
}

/// Writes an encrypted message into [out]: [data] as literal data of
/// [format] (`u` for typed text, `b` for a file) named [fileName], signed
/// by [signer] inside the encryption when given, to the key packets of
/// [recipients] or, when there are none, to [passphrase].
///
/// With [definite] the whole message is built in memory and every packet
/// has a definite length, as for a typed text; without it the encrypted
/// data and the literal data go out in partial lengths of 64 KiB, and
/// [data] may be a file of any size.
///
/// With [aead] the session keys go in version 6 PKESK packets and the data
/// in SEIPD version 2, AES-256 with OCB in chunks of 64 KiB; for every
/// recipient key that says it reads them, which the caller decides.
Future<void> writeEncryptedMessage({
  required ByteSource data,
  required ByteSink out,
  required List<KeyPacket> recipients,
  String? passphrase,
  MessageSigner? signer,
  required int format,
  String fileName = '',
  required bool definite,
  required MessageRandom random,
  required DateTime time,
  int s2kCount = defaultS2kCount,
  bool aead = false,
}) async {
  if (aead && recipients.isEmpty) throw ArgumentError('version 2 SEIPD is written to keys only');
  final Uint8List sessionKey;
  if (recipients.isNotEmpty) {
    sessionKey = random.sessionKey;
    for (final (i, recipient) in recipients.indexed) {
      final perRecipient = random.perRecipient[i];
      out.add(
        writePacket(
          PgpTag.pkesk,
          aead
              ? await writePkesk6(recipient, sessionKey, perRecipient)
              : await writePkesk3(recipient, cipherAes256, sessionKey, perRecipient),
        ),
      );
    }
  } else {
    if (passphrase == null || passphrase.isEmpty) throw ArgumentError('a message needs a recipient or a passphrase');
    final s2k = S2k.iterated(hashSha256, random.salt, s2kCount);
    sessionKey = s2k.derive(utf8.encode(passphrase), 32);
    out.add(writePacket(PgpTag.skesk, writeSkesk4(cipherAes256, s2k)));
  }

  if (aead) {
    final salt = random.aeadSalt ?? randomBytes(32);
    if (definite) {
      final inner = BytesSink();
      await writeSignedData(data: data, out: inner, signer: signer, format: format, fileName: fileName, definite: true, time: time);
      final plain = inner.takeBytes();
      const chunk = 1 << (defaultAeadChunkOctet + 6);
      final chunks = (plain.length + chunk - 1) ~/ chunk;
      // The 36 octets of the head, the data with a tag per chunk, the final tag
      final packet = PacketWriter(out, PgpTag.seipd, length: 36 + plain.length + 16 * chunks + 16);
      Seipd2Writer(sessionKey, salt, packet)
        ..add(plain)
        ..close();
      packet.close();
    } else {
      final packet = PacketWriter(out, PgpTag.seipd);
      final seipd = Seipd2Writer(sessionKey, salt, packet);
      await writeSignedData(data: data, out: seipd, signer: signer, format: format, fileName: fileName, definite: false, time: time);
      seipd.close();
      packet.close();
    }
    return;
  }
  if (definite) {
    final inner = BytesSink();
    await writeSignedData(data: data, out: inner, signer: signer, format: format, fileName: fileName, definite: true, time: time);
    final plain = inner.takeBytes();
    // The version octet, the 18-byte prefix, the data and the 22-byte MDC
    final packet = PacketWriter(out, PgpTag.seipd, length: 1 + 18 + plain.length + 22);
    Seipd1Writer(sessionKey, random.prefix, packet)
      ..add(plain)
      ..close();
    packet.close();
  } else {
    final packet = PacketWriter(out, PgpTag.seipd);
    final seipd = Seipd1Writer(sessionKey, random.prefix, packet);
    await writeSignedData(data: data, out: seipd, signer: signer, format: format, fileName: fileName, definite: false, time: time);
    seipd.close();
    packet.close();
  }
}

/// Writes [data] as a literal data packet into [out], between a one-pass
/// signature packet and the signature of [signer] when given: what goes
/// inside the encryption, and by itself an inline-signed message.
Future<void> writeSignedData({
  required ByteSource data,
  required ByteSink out,
  MessageSigner? signer,
  required int format,
  String fileName = '',
  required bool definite,
  required DateTime time,
}) async {
  final salt = signer == null ? null : signatureSaltFor(signer.key);
  final hasher = signer == null ? null : SignatureHasher.of(hashSha512, text: false, salt: salt)!;
  if (signer != null) out.add(writePacket(PgpTag.onePassSignature, onePassSignature(signatureBinary, signer.key, salt: salt)));
  final name = utf8.encode(fileName);
  if (name.length > 255) throw ArgumentError.value(fileName, 'fileName', 'too long');
  // The date is left at zero: when it was written is nobody's business
  final header = Uint8List.fromList([format, name.length, ...name, 0, 0, 0, 0]);
  if (definite) {
    final content = PgpReader(data).rest(max: 1 << 30);
    hasher?.add(content);
    PacketWriter(out, PgpTag.literalData, length: header.length + content.length)
      ..add(header)
      ..add(content)
      ..close();
  } else {
    final literal = PacketWriter(out, PgpTag.literalData)..add(header);
    for (var piece = data.next(); piece != null; piece = data.next()) {
      hasher?.add(piece);
      literal.add(piece);
    }
    literal.close();
  }
  if (signer != null) {
    final signature = await signData(
      hasher: hasher!,
      type: signatureBinary,
      signer: signer.key,
      secret: signer.secret,
      time: time,
      salt: salt,
    );
    out.add(writePacket(PgpTag.signature, signature));
  }
}

/// The detached signature packet of [signer] over [data]: of type 0x00,
/// or 0x01 when [text], in which case [data] is hashed with its line
/// endings as CR LF.
Future<Uint8List> writeDetachedSignature({
  required ByteSource data,
  required MessageSigner signer,
  bool text = false,
  required DateTime time,
}) async {
  final salt = signatureSaltFor(signer.key);
  final hasher = SignatureHasher.of(hashSha512, text: text, salt: salt)!;
  for (var piece = data.next(); piece != null; piece = data.next()) {
    hasher.add(piece);
  }
  final type = text ? signatureText : signatureBinary;
  return writePacket(
    PgpTag.signature,
    await signData(hasher: hasher, type: type, signer: signer.key, secret: signer.secret, time: time, salt: salt),
  );
}

/// Checks the detached [signatures], signature packets, over [data]
/// against [verifiers] at [now]: one result per signature.
Future<List<SignatureResult>> checkDetachedSignatures({
  required ByteSource data,
  required Uint8List signatures,
  required List<PgpCertificate> verifiers,
  required DateTime now,
}) async {
  final pending = <PendingSignature>[];
  try {
    final packets = PacketReader(PgpReader.bytes(signatures));
    for (var packet = packets.next(); packet != null; packet = packets.next()) {
      if (packet.tag == PgpTag.marker || packet.tag == PgpTag.padding) continue;
      if (packet.tag != PgpTag.signature) throw const PgpException(PgpProblem.notAMessage, detail: 'not a signature');
      final body = packet.body.rest(max: _maxSmallPacket);
      pending.add(PendingSignature.of(asPgpError(() => parseSignature(body))));
    }
  } on PgpException catch (e) {
    if (e.problem == PgpProblem.damaged && pending.isEmpty) throw const PgpException(PgpProblem.notAMessage);
    rethrow;
  }
  if (pending.isEmpty) throw const PgpException(PgpProblem.notAMessage);
  for (var piece = data.next(); piece != null; piece = data.next()) {
    for (final signature in pending) {
      signature.add(piece);
    }
  }
  return [for (final signature in pending) await signature.check(verifiers, now)];
}
