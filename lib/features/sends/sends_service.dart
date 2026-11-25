/// Making, listing, editing and deleting the account's Sends, over [KmHost] and the Send routes of the server
/// (`docs/plans/add-sends.md`, designs 4 and 5). Every call runs inside [KmHost.withAccount] after
/// [KmHost.requireHome], so Sends live on the home server only, and the account's keys are wiped when it returns.
///
/// Nothing about a Send is kept on the phone: the list is read again each time, and a Send's link is rebuilt from
/// its sealed key when it is asked for. The link key, the payload key and the meta key live only inside a call and
/// are wiped before it returns. The server gets ciphertext, the proof of a password and nothing else.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../crypto/account/argon2id.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/account/send.dart';
import '../../models/secure_note.dart' show attachmentSizeLimit;
import '../sync/kemlock/km_account.dart';
import '../sync/kemlock/km_api.dart';
import '../sync/kemlock/km_host.dart';
import '../sync/kemlock/km_models.dart';
import '../sync/kemlock/km_sends_api.dart';
import 'send_link.dart';

/// The largest file a Send is made from, the app's attachment limit.
const sendFileLimit = attachmentSizeLimit;

/// The most days ahead a Send's deletion may be.
const sendMaxDeleteDays = 30;

/// The choices of "Deletes after", in days.
const sendDeleteDayChoices = [1, 2, 3, 7, 14, 30];

/// Why an input was refused before anything was sealed or sent.
enum SendsInvalid {
  /// A Send needs a name.
  noName,

  /// A text Send needs a text.
  noText,

  /// The sealed payload would be over the server's 256 KiB.
  textTooLong,

  /// The sealed meta would be over the server's 16 KiB.
  notesTooLong,

  /// A file over [sendFileLimit].
  fileTooBig,

  /// The deletion isn't 1 to 30 days ahead.
  deletion,

  /// The link would stop working after the Send is deleted, or already has.
  expiry,

  /// An open limit under 1, or under the opens already used.
  maxAccess,
}

/// An input the service refused.
class SendsInvalidInput implements Exception {
  const SendsInvalidInput(this.reason);

  final SendsInvalid reason;

  @override
  String toString() => 'Send input refused: ${reason.name}';
}

/// A file Send's bytes didn't go up after three tries, and the Send was deleted so none waits closed.
class SendsUploadFailed implements Exception {
  const SendsUploadFailed(this.cause);

  /// The last failure.
  final Object cause;

  @override
  String toString() => 'The file did not go up: $cause';
}

/// What the New Send sheet gives: a text or a file, and the options.
class NewSend {
  /// A Send of [text].
  NewSend.text({
    required this.name,
    required String this.text,
    this.notes = '',
    this.deleteInDays = 7,
    this.expiresAt,
    this.maxAccess,
    this.password,
    this.hideEmail = false,
  }) : fileBytes = null,
       mime = null;

  /// A Send of the file [bytes], named [name] for the recipient, of media type [mime].
  NewSend.file({
    required this.name,
    required Uint8List bytes,
    required String this.mime,
    this.notes = '',
    this.deleteInDays = 7,
    this.expiresAt,
    this.maxAccess,
    this.password,
    this.hideEmail = false,
  }) : fileBytes = bytes,
       text = null;

  /// The name the recipient sees, and the owner's list shows.
  final String name;

  /// The text of a text Send, else null.
  final String? text;

  /// A file Send's plaintext, else null.
  final Uint8List? fileBytes;

  /// A file's media type, else null.
  final String? mime;

  /// Notes only the owner sees.
  final String notes;

  /// Deleted this many days from now, 1 to [sendMaxDeleteDays].
  final int deleteInDays;

  /// When the link stops working, no later than the deletion; null for never before it.
  final DateTime? expiresAt;

  /// How many times it may be opened, from 1; null for no limit.
  final int? maxAccess;

  /// An optional password. Empty means none. It is never sent: only its proof is.
  final String? password;

  final bool hideEmail;

  bool get isFile => fileBytes != null;
}

/// A Send made: the server's answer, and its link. The link holds the key: show it, copy it, share it, and let go.
class MadeSend {
  const MadeSend({required this.send, required this.link});

  final KmSend send;
  final String link;
}

/// What an owner's list shows of a Send, from the DTO alone.
enum SendStatus { active, expired, usedUp, off, waitingForFile }

/// The status of [send] at [now], in the plan's order: off, expired, used up, waiting for its file, else active.
SendStatus sendStatus(KmListedSend send, DateTime now) {
  if (send.disabled) return SendStatus.off;
  final expires = send.expiresAt;
  if (expires != null && !expires.isAfter(now)) return SendStatus.expired;
  final limit = send.maxAccess;
  if (limit != null && send.accessCount >= limit) return SendStatus.usedUp;
  final file = send.file;
  if (file != null && !file.ready) return SendStatus.waitingForFile;
  return SendStatus.active;
}

/// One of the account's Sends in the list: the server's [send] and what the account's own key read of its meta.
class OwnedSend {
  const OwnedSend({required this.send, required this.status, this.meta});

  final KmSend send;
  final SendStatus status;

  /// The owner's name and notes, or null when the meta doesn't open on this phone: "Can't be read on this phone",
  /// with Delete only.
  final SendMeta? meta;

  bool get readable => meta != null;
  bool get isFile => send.kind == sendKindFile;
}

/// One of the account's Sends that a Bitwarden app made: what the server keeps in plain ([send]) and its [status] from that.
/// Its key isn't Kemlock's, so nothing of it is opened: it can be seen and deleted, never opened, edited or shared here.
class ForeignSend {
  const ForeignSend({required this.send, required this.status});

  final KmForeignSend send;
  final SendStatus status;

  bool get isFile => send.kind == sendKindFile;
}

/// The account's Sends as the page shows them: the ones Kemlock made, opened with the account's key, and the ones a
/// Bitwarden app made, which are only listed.
class SendsListing {
  const SendsListing({required this.owned, this.foreign = const []});

  final List<OwnedSend> owned;
  final List<ForeignSend> foreign;

  bool get isEmpty => owned.isEmpty && foreign.isEmpty;
}

/// What an edit changes. The server replaces every option, so every one is given.
class SendEdit {
  const SendEdit({
    required this.name,
    required this.notes,
    required this.deletionAt,
    this.text,
    this.expiresAt,
    this.maxAccess,
    this.hideEmail = false,
    this.disabled = false,
    this.newPassword,
    this.removePassword = false,
  });

  /// The new name. A file Send keeps its own.
  final String name;
  final String notes;

  /// The new text of a text Send; null keeps it.
  final String? text;
  final DateTime deletionAt;
  final DateTime? expiresAt;

  /// The open limit, from the opens used; null for none.
  final int? maxAccess;
  final bool hideEmail;
  final bool disabled;

  /// A new password, set or changed; null or empty keeps it.
  final String? newPassword;

  /// Takes the password away. Not together with [newPassword].
  final bool removePassword;
}

/// The owner's Sends.
class SendsService {
  SendsService({required this.host, required this.target, this.clock = DateTime.now, this.proofRunner = isolateArgon2id});

  final KmHost host;
  final KemlockTarget target;
  final DateTime Function() clock;

  /// Runs Argon2id for the password proof, [isolateArgon2id] by default.
  final Argon2idRunner proofRunner;

  Future<T> _run<T>(Future<T> Function(KmConnection connection, KmSendsApi sends, Uint8List itemWrapKey, KmAccount account) action) async {
    host.requireHome(target);
    return host.withAccount(target, (connection, account) async {
      final session = account.openSession();
      try {
        return await action(connection, KmSendsApi(connection.api), session.keys.itemWrapKey, account);
      } finally {
        session.dispose();
      }
    });
  }

  // ─── Making ────────────────────────────────────────────────────────────

  /// Makes a Send, and for a file uploads its bytes, then gives the link. A taken id is answered once with a new one.
  /// A file that doesn't go up after three tries is deleted again, and [SendsUploadFailed] says so.
  Future<MadeSend> make(NewSend input) async {
    final now = clock();
    _checkNew(input, now);
    return _run((connection, sends, itemWrapKey, account) async {
      for (var attempt = 0; ; attempt++) {
        try {
          return await _makeOnce(connection, sends, itemWrapKey, account.keyVersion, input, now);
        } on SendsError catch (e) {
          if (e.problem != SendsProblem.taken || attempt > 0) rethrow;
        }
      }
    });
  }

  Future<MadeSend> _makeOnce(
    KmConnection connection,
    KmSendsApi sends,
    Uint8List itemWrapKey,
    int keyVersion,
    NewSend input,
    DateTime now,
  ) async {
    final sendId = newSendId();
    final linkKey = newSendLinkKey();
    final payloadKey = sendPayloadKey(linkKey);
    final metaKey = sendMetaKey(itemWrapKey, sendId, keyVersion);
    Uint8List? proof;
    try {
      final kind = input.isFile ? sendKindFile : sendKindText;
      final payload = input.isFile
          ? SendPayload.file(name: input.name, mime: input.mime!, size: input.fileBytes!.length)
          : SendPayload.text(name: input.name, text: input.text!);
      final sealedPayload = await sealSendPart(
        sealLabel: SendLabel.payload,
        key: payloadKey,
        sendId: sendId,
        kind: kind,
        plaintext: payload.encode(),
      );
      if (sealedPayload.length > sendMaxPayloadLength) throw const SendsInvalidInput(SendsInvalid.textTooLong);
      final sealedMeta = await sealSendPart(
        sealLabel: SendLabel.meta,
        key: metaKey,
        sendId: sendId,
        kind: kind,
        plaintext: SendMeta(name: input.name, notes: input.notes).encode(),
      );
      if (sealedMeta.length > sendMaxMetaLength) throw const SendsInvalidInput(SendsInvalid.notesTooLong);
      final sealedKey = await wrapLinkKey(itemWrapKey: itemWrapKey, sendId: sendId, keyVersion: keyVersion, linkKey: linkKey);
      final password = input.password;
      if (password != null && password.isNotEmpty) {
        proof = await sendProof(password, linkKey, sendId, runner: proofRunner);
      }
      final file = input.isFile ? await sealSendFile(input.fileBytes!, linkKey) : null;
      final request = KmNewSend(
        id: uuidText(sendId),
        kind: kind,
        meta: sealedMeta,
        sealedKey: sealedKey,
        payload: sealedPayload,
        fileSize: file?.length,
        maxAccess: input.maxAccess,
        hideEmail: input.hideEmail,
        expiresAt: input.expiresAt,
        deletionAt: now.add(Duration(days: input.deleteInDays)),
        password: proof,
      );
      var made = await connection.call((token) => sends.create(connection.server, token, request));
      if (file != null) {
        made = await _upload(connection, sends, made, file);
      }
      return MadeSend(send: made, link: sendLink(connection.server, sendId, linkKey));
    } finally {
      wipe(linkKey);
      wipe(payloadKey);
      wipe(metaKey);
      if (proof != null) wipe(proof);
    }
  }

  /// Puts a file Send's bytes up, with two more tries, and deletes the Send when they don't go.
  Future<KmSend> _upload(KmConnection connection, KmSendsApi sends, KmSend made, Uint8List file) async {
    final address = made.uploadUrl;
    Object? last;
    if (address != null) {
      for (var attempt = 0; attempt < 3; attempt++) {
        try {
          return await connection.call((token) => sends.upload(connection.server, token, made.id, address, file));
        } on SendsError catch (e) {
          // A file that is in already means an earlier try got through and its answer was lost
          if (e.problem == SendsProblem.alreadyUploaded) {
            return connection.call((token) => sends.get(connection.server, token, made.id));
          }
          last = e;
          break;
        } on KmError catch (e) {
          if (e.problem != KmProblem.network && e.problem != KmProblem.server) rethrow;
          last = e;
        }
      }
    }
    // No Send is left waiting closed for the server's 24-hour purge
    try {
      await connection.call((token) => sends.delete(connection.server, token, made.id));
    } on Object {
      // Best effort: the server purges it itself
    }
    throw SendsUploadFailed(last ?? const FormatException('the server gave no upload address'));
  }

  void _checkNew(NewSend input, DateTime now) {
    if (input.name.trim().isEmpty) throw const SendsInvalidInput(SendsInvalid.noName);
    if (input.isFile) {
      if (input.fileBytes!.length > sendFileLimit) throw const SendsInvalidInput(SendsInvalid.fileTooBig);
    } else if (input.text!.isEmpty) {
      throw const SendsInvalidInput(SendsInvalid.noText);
    }
    if (input.deleteInDays < 1 || input.deleteInDays > sendMaxDeleteDays) {
      throw const SendsInvalidInput(SendsInvalid.deletion);
    }
    final deletion = now.add(Duration(days: input.deleteInDays));
    final expires = input.expiresAt;
    if (expires != null && (expires.isAfter(deletion) || !expires.isAfter(now))) {
      throw const SendsInvalidInput(SendsInvalid.expiry);
    }
    final limit = input.maxAccess;
    if (limit != null && limit < 1) throw const SendsInvalidInput(SendsInvalid.maxAccess);
  }

  // ─── Listing, viewing, linking ─────────────────────────────────────────

  /// The account's Sends, newest first, Kemlock's and a Bitwarden app's apart. Each Kemlock Send's meta is opened with
  /// the key its `sealedKey` names; one that doesn't open is listed with no meta. A Bitwarden app's Send is listed
  /// from the server's plain fields alone, and nothing of it is decrypted.
  Future<SendsListing> listing() => _run((connection, sends, itemWrapKey, account) async {
    final listed = await connection.call((token) => sends.list(connection.server, token));
    final now = clock();
    final owned = <OwnedSend>[];
    final foreign = <ForeignSend>[];
    for (final send in listed) {
      switch (send) {
        case KmSend():
          owned.add(OwnedSend(send: send, status: sendStatus(send, now), meta: await _readMeta(itemWrapKey, send)));
        case KmForeignSend():
          foreign.add(ForeignSend(send: send, status: sendStatus(send, now)));
      }
    }
    return SendsListing(owned: owned, foreign: foreign);
  });

  /// The Sends Kemlock made, newest first: [listing] without the ones a Bitwarden app made.
  Future<List<OwnedSend>> list() async => (await listing()).owned;

  Future<SendMeta?> _readMeta(Uint8List itemWrapKey, KmSend send) async {
    final metaKey = sendMetaKey(itemWrapKey, uuidBytes(send.id), sealedKeyVersion(send.sealedKey));
    try {
      final plain = await openSendPart(
        sealLabel: SendLabel.meta,
        key: metaKey,
        sendId: uuidBytes(send.id),
        kind: send.kind,
        sealed: send.meta,
      );
      return SendMeta.parse(plain);
    } on CorruptedException {
      return null;
    } on MalformedException {
      return null;
    } finally {
      wipe(metaKey);
    }
  }

  /// The link of [owned], rebuilt from its sealed key. The link holds the key, so it goes to the secret clipboard or
  /// the share sheet and nowhere else.
  Future<String> linkOf(OwnedSend owned) => _run((connection, sends, itemWrapKey, account) async {
    final sendId = uuidBytes(owned.send.id);
    final linkKey = await unwrapLinkKey(itemWrapKey: itemWrapKey, sendId: sendId, sealedKey: owned.send.sealedKey);
    try {
      return sendLink(connection.server, sendId, linkKey);
    } finally {
      wipe(linkKey);
    }
  });

  /// The text of a text Send, opened from its DTO with the key from its sealed key. It makes no public request, so
  /// it spends no open.
  Future<SendPayload> view(OwnedSend owned) => _run((connection, sends, itemWrapKey, account) => _readPayload(itemWrapKey, owned.send));

  Future<SendPayload> _readPayload(Uint8List itemWrapKey, KmSend send) async {
    final sendId = uuidBytes(send.id);
    final linkKey = await unwrapLinkKey(itemWrapKey: itemWrapKey, sendId: sendId, sealedKey: send.sealedKey);
    final payloadKey = sendPayloadKey(linkKey);
    try {
      final plain = await openSendPart(
        sealLabel: SendLabel.payload,
        key: payloadKey,
        sendId: sendId,
        kind: send.kind,
        sealed: send.payload,
      );
      return SendPayload.parse(plain, send.kind);
    } finally {
      wipe(linkKey);
      wipe(payloadKey);
    }
  }

  // ─── Editing and deleting ──────────────────────────────────────────────

  /// Changes [owned]: its meta sealed again with a fresh nonce, a text Send's payload sealed again under the same
  /// link key when its text or name changed, every option, and the password (set, changed or removed). The key, the
  /// file and the open count never change, so the old link still opens the Send.
  Future<KmSend> update(OwnedSend owned, SendEdit edit) async {
    final send = owned.send;
    final now = clock();
    if (edit.name.trim().isEmpty) throw const SendsInvalidInput(SendsInvalid.noName);
    final deletionDays = edit.deletionAt.difference(now);
    if (!edit.deletionAt.isAfter(now) || deletionDays > const Duration(days: sendMaxDeleteDays)) {
      throw const SendsInvalidInput(SendsInvalid.deletion);
    }
    final expires = edit.expiresAt;
    if (expires != null && expires.isAfter(edit.deletionAt)) throw const SendsInvalidInput(SendsInvalid.expiry);
    final limit = edit.maxAccess;
    if (limit != null && (limit < 1 || limit < send.accessCount)) throw const SendsInvalidInput(SendsInvalid.maxAccess);
    if (edit.text != null && edit.text!.isEmpty && !owned.isFile) throw const SendsInvalidInput(SendsInvalid.noText);
    final newPassword = edit.newPassword != null && edit.newPassword!.isNotEmpty ? edit.newPassword : null;
    return _run((connection, sends, itemWrapKey, account) async {
      final sendId = uuidBytes(send.id);
      final version = sealedKeyVersion(send.sealedKey);
      final linkKey = await unwrapLinkKey(itemWrapKey: itemWrapKey, sendId: sendId, sealedKey: send.sealedKey);
      final payloadKey = sendPayloadKey(linkKey);
      final metaKey = sendMetaKey(itemWrapKey, sendId, version);
      Uint8List? proof;
      try {
        // A file Send's name is its file's and can't change
        final name = owned.isFile ? (owned.meta?.name ?? edit.name) : edit.name;
        final sealedMeta = await sealSendPart(
          sealLabel: SendLabel.meta,
          key: metaKey,
          sendId: sendId,
          kind: send.kind,
          plaintext: SendMeta(name: name, notes: edit.notes).encode(),
        );
        if (sealedMeta.length > sendMaxMetaLength) throw const SendsInvalidInput(SendsInvalid.notesTooLong);
        Uint8List? sealedPayload;
        if (!owned.isFile) {
          final current = SendPayload.parse(
            await openSendPart(sealLabel: SendLabel.payload, key: payloadKey, sendId: sendId, kind: send.kind, sealed: send.payload),
            send.kind,
          );
          final text = edit.text ?? current.text!;
          if (text != current.text || name != current.name) {
            sealedPayload = await sealSendPart(
              sealLabel: SendLabel.payload,
              key: payloadKey,
              sendId: sendId,
              kind: send.kind,
              plaintext: SendPayload.text(name: name, text: text).encode(),
            );
            if (sealedPayload.length > sendMaxPayloadLength) throw const SendsInvalidInput(SendsInvalid.textTooLong);
          }
        }
        if (newPassword != null) proof = await sendProof(newPassword, linkKey, sendId, runner: proofRunner);
        final request = KmSendUpdate(
          meta: sealedMeta,
          payload: sealedPayload,
          maxAccess: edit.maxAccess,
          hideEmail: edit.hideEmail,
          disabled: edit.disabled,
          expiresAt: edit.expiresAt,
          deletionAt: edit.deletionAt,
          password: proof,
          removePassword: proof == null && edit.removePassword,
        );
        return await connection.call((token) => sends.update(connection.server, token, send.id, request));
      } finally {
        wipe(linkKey);
        wipe(payloadKey);
        wipe(metaKey);
        if (proof != null) wipe(proof);
      }
    });
  }

  /// Deletes [owned] and its file. A Send that is gone already counts as deleted.
  Future<void> delete(OwnedSend owned) => deleteById(owned.send.id);

  /// Deletes a Send that a Bitwarden app made, with the same route. A Send that is gone already counts as deleted.
  Future<void> deleteForeign(ForeignSend foreign) => deleteById(foreign.send.id);

  /// Deletes the Send [id]. A Send that is gone already counts as deleted.
  Future<void> deleteById(String id) => _run((connection, sends, itemWrapKey, account) {
    return connection.call((token) => sends.delete(connection.server, token, id));
  });
}
