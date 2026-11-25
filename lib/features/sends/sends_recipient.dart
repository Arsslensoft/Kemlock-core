/// Opening a Send as a recipient, with no account (`docs/plans/add-sends.md`, designs 7 and 8). The public routes take
/// no token and no proof of device, so this needs neither a Kemlock Server sign-in nor sync, only a link.
///
/// - The client is the app's gated one, made through the Kemlock client factory with no pin: system trust only, as a
///   recipient has never seen the server. Offline mode refuses it, and a link that isn't https is refused before any
///   request.
/// - The link's key goes into no request, header, error or log: [SendsRecipient] hands the server the access id, and
///   the proof of the password when there is one, and nothing else.
/// - A payload that doesn't open under the link's key with this id and kind, or isn't exactly its kind's JSON, or a
///   file whose announced length isn't the `KMA1` length of its payload's size, shows nothing ([SendsDoesntOpen]).
/// - A file's bytes are fetched only on [SendsRecipient.download], which is when the server counts an open, and are
///   held in memory: the caller decides whether to write them.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../../crypto/account/argon2id.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/account/send.dart';
import '../../crypto/attachment_format.dart';
import '../sync/kemlock/km_api.dart';
import '../sync/kemlock/km_sends_api.dart';
import 'send_link.dart';
import 'sends_service.dart' show sendFileLimit;

/// The link opened with a payload the key doesn't open, one that isn't exactly its kind's, or a file whose length
/// isn't its payload's. Nothing of the Send is shown.
class SendsDoesntOpen implements Exception {
  const SendsDoesntOpen();

  @override
  String toString() => 'The Send does not open';
}

/// A file over [sendFileLimit], which the app doesn't download. The browser may open it.
class SendsFileTooBig implements Exception {
  const SendsFileTooBig(this.size);

  /// What the payload says, in bytes.
  final int size;

  @override
  String toString() => 'The Send file is too big for the app';
}

/// A Send a recipient opened: what its payload says, and what the server added. It holds the link's key and the
/// proof of the password, so [dispose] it when the sheet closes.
class ReceivedSend {
  ReceivedSend._({
    required this.link,
    required this.payload,
    required this.deletionAt,
    this.fileSize,
    this.expiresAt,
    this.senderEmail,
    this._proof,
  });

  final SendLink link;
  final SendPayload payload;

  /// A file Send's `KMA1` length, checked against the payload's size.
  final int? fileSize;
  final DateTime? expiresAt;
  final DateTime deletionAt;

  /// The server's word about who sent it, when it is shown: at most 254 characters, with no control characters.
  final String? senderEmail;

  Uint8List? _proof;

  bool get isFile => payload.kind == sendKindFile;

  /// A file over the app's limit, which [SendsRecipient.download] refuses; the sheet offers the browser.
  bool get tooBig => isFile && payload.size! > sendFileLimit;

  /// Zeroes the link's key and the proof. The Send can't be opened or downloaded afterwards.
  void dispose() {
    link.wipeKey();
    final proof = _proof;
    if (proof != null) wipe(proof);
    _proof = null;
  }
}

/// What the sender's email must be to be shown: at most 254 characters, with no control characters.
String? shownSenderEmail(String? email) {
  if (email == null || email.isEmpty || email.length > 254) return null;
  if (RegExp(r'[\x00-\x1f\x7f]').hasMatch(email)) return null;
  return email;
}

/// Opens Sends from their links.
class SendsRecipient {
  SendsRecipient({required this.clientFor, this.proofRunner = isolateArgon2id});

  /// The gated client factory (`kemlockClientFactoryProvider`), asked with no pin.
  final http.Client Function(String? pin) clientFor;

  /// Runs Argon2id for the password proof.
  final Argon2idRunner proofRunner;

  /// The client for [link], after its address is checked: https, or a [KmError] with problem `insecure`, before any
  /// client is made.
  http.Client _client(SendLink link) {
    if (link.server.scheme != 'https') throw const KmError(KmProblem.insecure);
    return clientFor(null);
  }

  /// Opens [link]. Without a [password] a Send that has one throws [SendsError] `passwordRequired`; with a wrong one,
  /// `wrongPassword`, and after too many, `rateLimited`. A Send that is closed is `notFound`, and the server doesn't
  /// say why. A text Send counts an open here; a file Send doesn't, until [download].
  ///
  /// The proof of a [password] is made first, once, and kept for the file's download.
  Future<ReceivedSend> open(SendLink link, {String? password}) async {
    final client = _client(link);
    Uint8List? proof;
    try {
      if (password != null && password.isNotEmpty) {
        proof = await sendProof(password, link.key, link.sendId, runner: proofRunner);
      }
      final access = await KmSendsApi(KmApi(client)).access(link.server, link.accessId, password: proof);
      final received = await _read(link, access, proof);
      proof = null;
      return received;
    } finally {
      client.close();
      if (proof != null) wipe(proof);
    }
  }

  Future<ReceivedSend> _read(SendLink link, KmSendAccess access, Uint8List? proof) async {
    final payloadKey = sendPayloadKey(link.key);
    try {
      final SendPayload payload;
      try {
        final plain = await openSendPart(
          sealLabel: SendLabel.payload,
          key: payloadKey,
          sendId: link.sendId,
          kind: access.kind,
          sealed: access.payload,
        );
        payload = SendPayload.parse(plain, access.kind);
      } on CorruptedException {
        throw const SendsDoesntOpen();
      } on MalformedException {
        throw const SendsDoesntOpen();
      }
      if (payload.kind == sendKindFile) {
        final fileSize = access.fileSize;
        if (fileSize == null || !sendFileLengthMatches(payload.size!, fileSize)) throw const SendsDoesntOpen();
      }
      return ReceivedSend._(
        link: link,
        payload: payload,
        fileSize: access.fileSize,
        expiresAt: access.expiresAt,
        deletionAt: access.deletionAt,
        senderEmail: shownSenderEmail(access.senderEmail),
        proof: proof,
      );
    } finally {
      wipe(payloadKey);
    }
  }

  /// A file Send's plaintext: `POST …/file`, which spends an open, then `KMA1` opened in an isolate. A file over
  /// [sendFileLimit] is [SendsFileTooBig], with no request. The server may send no more than the length the Send
  /// named. The bytes are the caller's to drop and zero.
  Future<Uint8List> download(ReceivedSend send) async {
    final fileSize = send.fileSize;
    if (!send.isFile || fileSize == null) throw const SendsDoesntOpen();
    if (send.tooBig) throw SendsFileTooBig(send.payload.size!);
    final client = _client(send.link);
    try {
      final bytes = await KmSendsApi(KmApi(client))
          .download(send.link.server, send.link.accessId, fileSize: fileSize, password: send._proof);
      try {
        return await openSendFile(bytes, send.link.key, send.payload.size!);
      } on MalformedException {
        throw const SendsDoesntOpen();
      } on AttachmentDamagedError {
        throw const SendsDoesntOpen();
      } finally {
        wipe(bytes);
      }
    } finally {
      client.close();
    }
  }
}
