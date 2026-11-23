/// The Kemlock API's Send routes (`crates/kemlock-api-kem/src/routes/sends.rs`), over [KmApi] so they share its
/// limits: no redirect, a read cap and a timeout on every request. The owner's routes carry a token and a DPoP proof;
/// the public routes of a link carry neither, whoever asks. Binary values are base64url without padding and times are
/// Unix seconds. Shapes are the server's, as `test/fixtures/kemlock/README.md` records.
///
/// The link key `K` goes into none of these requests: this file never sees it, only what the Send's seals make of it.
/// It logs nothing, and no error here names a link, a proof or a key.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/send.dart';
import 'km_api.dart';

/// Why a Send request failed, when the server's own words tell: the problems of the Send routes. A failure with no
/// meaning here (the network, an ended session) stays the [KmError] it was.
enum SendsProblem {
  /// 401 `send-password-required`: the Send has a password and the request carried no proof.
  passwordRequired,

  /// 401 `send-wrong-password`.
  wrongPassword,

  /// 403 `send-policy`: a policy of one of the owner's spaces forbids it; [SendsError.detail] says which.
  policy,

  /// 413 `file-too-large`: [SendsError.maxSize] is what the server takes.
  fileTooLarge,

  /// 403 `storage-disabled`, 413 `storage-limit-reached` or `storage-limit-exceeded`: the account's storage.
  storage,

  /// 404: no such Send, or one that is closed. The server doesn't say which.
  notFound,

  /// 409 `already-exists`: the id is taken.
  taken,

  /// 409 `already-uploaded`: the file's bytes are in already.
  alreadyUploaded,

  /// 400 `length-mismatch` or 415 `not-kma1`: the upload isn't what the Send announced.
  uploadRefused,

  /// 429: too many password tries; [SendsError.retryAfter] is the wait in seconds.
  rateLimited,
}

/// A Send request the server refused for one of the [SendsProblem]s.
class SendsError implements Exception {
  const SendsError(this.problem, {this.detail, this.maxSize, this.retryAfter, this.status = 0});

  final SendsProblem problem;

  /// The server's own words, for `send-policy` and the storage refusals.
  final String? detail;

  /// For [SendsProblem.fileTooLarge]: the largest file the server takes.
  final int? maxSize;

  /// For [SendsProblem.rateLimited]: seconds to wait.
  final int? retryAfter;
  final int status;

  @override
  String toString() => 'Send ${problem.name}${status != 0 ? ' ($status)' : ''}';
}

/// [error] as a [SendsError] when it is one of the Send routes' refusals, else the [error] itself, to be rethrown.
Exception sendsFailure(KmError error) {
  final status = error.status;
  switch (error.slug) {
    case 'send-password-required':
      return SendsError(SendsProblem.passwordRequired, status: status);
    case 'send-wrong-password':
      return SendsError(SendsProblem.wrongPassword, status: status);
    case 'send-policy':
      return SendsError(SendsProblem.policy, detail: error.message, status: status);
    case 'file-too-large':
      return SendsError(SendsProblem.fileTooLarge, maxSize: error.maxSize, status: status);
    case 'storage-disabled' || 'storage-limit-reached' || 'storage-limit-exceeded':
      return SendsError(SendsProblem.storage, detail: error.message, status: status);
    case 'already-exists':
      return SendsError(SendsProblem.taken, status: status);
    case 'already-uploaded':
      return SendsError(SendsProblem.alreadyUploaded, status: status);
    case 'length-mismatch' || 'not-kma1':
      return SendsError(SendsProblem.uploadRefused, detail: error.message, status: status);
  }
  if (status == 404) return SendsError(SendsProblem.notFound, status: status);
  if (status == 429) return SendsError(SendsProblem.rateLimited, retryAfter: error.retryAfter, status: status);
  return error;
}

/// A file Send's bytes as the owner sees them.
class KmSendFile {
  const KmSendFile({required this.size, required this.ready});

  /// The length of the `KMA1` file.
  final int size;

  /// Whether the bytes have arrived. A file Send that is not ready can't be opened.
  final bool ready;
}

/// A Send of the account's list: one the Kemlock routes made ([KmSend]), or one a Bitwarden app made ([KmForeignSend]).
/// Both hold what the server keeps in plain: the dates, the open count and limit, and the on and off switch.
sealed class KmListedSend {
  /// The Send's id, a UUID.
  String get id;

  /// The id the link carries.
  String get accessId;

  /// `text` or `file`.
  String get kind;

  /// A file Send's file, null for a text.
  KmSendFile? get file;
  bool get hasPassword;
  int? get maxAccess;
  int get accessCount;
  bool get hideEmail;
  bool get disabled;
  DateTime? get expiresAt;
  DateTime get deletionAt;
  DateTime get createdAt;
  DateTime get revisedAt;
}

/// Reads the fields of one Send object of an answer; a field of the wrong type is a [FormatException].
class _SendReader {
  const _SendReader(this.json);

  final Map<String, Object?> json;

  String string(String name) {
    final value = json[name];
    if (value is! String) throw FormatException('$name is a string');
    return value;
  }

  int integer(String name) {
    final value = json[name];
    if (value is! int) throw FormatException('$name is an integer');
    return value;
  }

  int? optionalInteger(String name) {
    final value = json[name];
    if (value == null) return null;
    if (value is! int) throw FormatException('$name is an integer');
    return value;
  }

  bool boolean(String name) {
    final value = json[name];
    if (value is! bool) throw FormatException('$name is a boolean');
    return value;
  }

  Uint8List bytes(String name, {int minimum = 0}) {
    try {
      final value = b64urlDecode(string(name));
      if (value.length < minimum) throw FormatException('$name is too short');
      return value;
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    }
  }

  /// The id, access id and kind, which must agree: a UUID, its own access id, and `text` or `file`.
  ({String id, String accessId, String kind}) identity() {
    final id = string('id');
    final accessId = string('accessId');
    final kind = string('kind');
    if (!isUuidText(id)) throw const FormatException('a Send id is a UUID');
    if (kind != sendKindText && kind != sendKindFile) throw FormatException('unknown Send kind: $kind');
    try {
      if (sendAccessId(uuidBytes(id)) != accessId) throw const FormatException('the access id is not the Send id');
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    }
    return (id: id, accessId: accessId, kind: kind);
  }

  KmSendFile? file() {
    final file = json['file'];
    if (file == null) return null;
    if (file is! Map<String, Object?> || file['size'] is! int || file['ready'] is! bool) {
      throw const FormatException('a Send file is a size and a ready flag');
    }
    return KmSendFile(size: file['size']! as int, ready: file['ready']! as bool);
  }
}

/// A Send as its owner sees it (the server's `SendDto`).
class KmSend implements KmListedSend {
  const KmSend({
    required this.id,
    required this.accessId,
    required this.kind,
    required this.meta,
    required this.sealedKey,
    required this.payload,
    required this.hasPassword,
    required this.accessCount,
    required this.hideEmail,
    required this.disabled,
    required this.deletionAt,
    required this.createdAt,
    required this.revisedAt,
    this.file,
    this.maxAccess,
    this.expiresAt,
    this.uploadUrl,
  });

  /// Reads one Send of an answer. A field of the wrong type, an id that isn't a UUID or doesn't match its access id,
  /// a `sealedKey` that isn't 64 bytes, a sealed part under 28 bytes, or base64url that isn't canonical is a
  /// [FormatException].
  factory KmSend.fromJson(Object? json) {
    if (json is! Map<String, Object?>) throw const FormatException('a Send is an object');
    final reader = _SendReader(json);
    final (:id, :accessId, :kind) = reader.identity();
    final sealedKey = reader.bytes('sealedKey');
    if (sealedKey.length != sendSealedKeyLength) throw const FormatException('sealedKey is 64 bytes');
    final sendFile = reader.file();
    final upload = json['uploadUrl'];
    if (upload != null && upload is! String) throw const FormatException('uploadUrl is a string');
    return KmSend(
      id: id,
      accessId: accessId,
      kind: kind,
      meta: reader.bytes('meta', minimum: sendMinimumSealedLength),
      sealedKey: sealedKey,
      payload: reader.bytes('payload', minimum: sendMinimumSealedLength),
      file: sendFile,
      hasPassword: reader.boolean('hasPassword'),
      maxAccess: reader.optionalInteger('maxAccess'),
      accessCount: reader.integer('accessCount'),
      hideEmail: reader.boolean('hideEmail'),
      disabled: reader.boolean('disabled'),
      expiresAt: _time(reader.optionalInteger('expiresAt')),
      deletionAt: _time(reader.integer('deletionAt'))!,
      createdAt: _time(reader.integer('createdAt'))!,
      revisedAt: _time(reader.integer('revisedAt'))!,
      uploadUrl: upload as String?,
    );
  }

  @override
  final String id;

  @override
  final String accessId;

  @override
  final String kind;

  /// The owner's sealed name and notes.
  final Uint8List meta;

  /// The link key sealed under the owner's item-wrap key, 64 bytes.
  final Uint8List sealedKey;

  /// What a recipient opens, sealed under the payload key.
  final Uint8List payload;

  @override
  final KmSendFile? file;
  @override
  final bool hasPassword;
  @override
  final int? maxAccess;
  @override
  final int accessCount;
  @override
  final bool hideEmail;
  @override
  final bool disabled;
  @override
  final DateTime? expiresAt;
  @override
  final DateTime deletionAt;
  @override
  final DateTime createdAt;
  @override
  final DateTime revisedAt;

  /// Where to `PUT` a file Send's bytes; only in the answer that makes it.
  final String? uploadUrl;
}

/// A Send the account made from a Bitwarden app. The Bitwarden API keeps its Sends in the same table as the Kemlock
/// routes, and the list returns them with a `sealedKey` that is the UTF-8 of Bitwarden's encrypted key string, never
/// the 64 bytes of a Kemlock Send. Its key isn't Kemlock's, so nothing of it is opened: this holds only what the server
/// keeps in plain, and the page can show it and delete it, nothing more.
class KmForeignSend implements KmListedSend {
  const KmForeignSend({
    required this.id,
    required this.accessId,
    required this.kind,
    required this.hasPassword,
    required this.accessCount,
    required this.hideEmail,
    required this.disabled,
    required this.deletionAt,
    required this.createdAt,
    required this.revisedAt,
    this.file,
    this.maxAccess,
    this.expiresAt,
  });

  /// Reads one Send of the list that a Bitwarden app made. Its `meta`, `sealedKey` and `payload` are never decoded
  /// here. A field of the wrong type, or an id that isn't a UUID or doesn't match its access id, is a [FormatException].
  factory KmForeignSend.fromJson(Object? json) {
    if (json is! Map<String, Object?>) throw const FormatException('a Send is an object');
    final reader = _SendReader(json);
    final (:id, :accessId, :kind) = reader.identity();
    return KmForeignSend(
      id: id,
      accessId: accessId,
      kind: kind,
      file: reader.file(),
      hasPassword: reader.boolean('hasPassword'),
      maxAccess: reader.optionalInteger('maxAccess'),
      accessCount: reader.integer('accessCount'),
      hideEmail: reader.boolean('hideEmail'),
      disabled: reader.boolean('disabled'),
      expiresAt: _time(reader.optionalInteger('expiresAt')),
      deletionAt: _time(reader.integer('deletionAt'))!,
      createdAt: _time(reader.integer('createdAt'))!,
      revisedAt: _time(reader.integer('revisedAt'))!,
    );
  }

  @override
  final String id;

  @override
  final String accessId;

  @override
  final String kind;

  @override
  final KmSendFile? file;
  @override
  final bool hasPassword;
  @override
  final int? maxAccess;
  @override
  final int accessCount;
  @override
  final bool hideEmail;
  @override
  final bool disabled;
  @override
  final DateTime? expiresAt;
  @override
  final DateTime deletionAt;
  @override
  final DateTime createdAt;
  @override
  final DateTime revisedAt;
}

/// What a recipient gets of a Send (the server's `AccessDto`): ciphertext and dates.
class KmSendAccess {
  const KmSendAccess({
    required this.id,
    required this.kind,
    required this.payload,
    required this.deletionAt,
    this.fileSize,
    this.expiresAt,
    this.senderEmail,
  });

  /// Reads an access answer. A field of the wrong type, or a payload under 28 bytes, is a [FormatException].
  factory KmSendAccess.fromJson(Object? json) {
    if (json is! Map<String, Object?>) throw const FormatException('an access is an object');
    final id = json['id'];
    final kind = json['kind'];
    final payload = json['payload'];
    final fileSize = json['fileSize'];
    final expiresAt = json['expiresAt'];
    final deletionAt = json['deletionAt'];
    final email = json['senderEmail'];
    if (id is! String || kind is! String || payload is! String) throw const FormatException('an access names its id, kind and payload');
    if (fileSize != null && fileSize is! int) throw const FormatException('fileSize is an integer');
    if (expiresAt != null && expiresAt is! int) throw const FormatException('expiresAt is an integer');
    if (deletionAt is! int) throw const FormatException('deletionAt is an integer');
    if (email != null && email is! String) throw const FormatException('senderEmail is a string');
    try {
      final sealed = b64urlDecode(payload);
      if (sealed.length < sendMinimumSealedLength) throw const FormatException('the payload is too short');
      return KmSendAccess(
        id: id,
        kind: kind,
        payload: sealed,
        fileSize: fileSize as int?,
        expiresAt: _time(expiresAt as int?),
        deletionAt: _time(deletionAt)!,
        senderEmail: email as String?,
      );
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    }
  }

  /// The access id.
  final String id;
  final String kind;
  final Uint8List payload;

  /// A file Send's `KMA1` length.
  final int? fileSize;
  final DateTime? expiresAt;
  final DateTime deletionAt;

  /// The sender's email, unless they hid it. It is the server's word, not signed by the sender.
  final String? senderEmail;
}

DateTime? _time(int? seconds) => seconds == null ? null : DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

int? _seconds(DateTime? time) => time == null ? null : time.millisecondsSinceEpoch ~/ 1000;

/// What `POST /sends` takes.
class KmNewSend {
  const KmNewSend({
    required this.id,
    required this.kind,
    required this.meta,
    required this.sealedKey,
    required this.payload,
    required this.deletionAt,
    this.fileSize,
    this.maxAccess,
    this.hideEmail = false,
    this.disabled = false,
    this.expiresAt,
    this.password,
  });

  /// The Send's id, a hyphenated version 4 UUID the client chose.
  final String id;
  final String kind;
  final Uint8List meta;
  final Uint8List sealedKey;
  final Uint8List payload;

  /// A file Send's announced `KMA1` length.
  final int? fileSize;
  final int? maxAccess;
  final bool hideEmail;
  final bool disabled;
  final DateTime? expiresAt;
  final DateTime deletionAt;

  /// The password proof, 32 bytes, or null for no password.
  final Uint8List? password;

  Map<String, Object?> toJson() => {
    'id': id,
    'kind': kind,
    'meta': b64urlEncode(meta),
    'sealedKey': b64urlEncode(sealedKey),
    'payload': b64urlEncode(payload),
    if (fileSize != null) 'file': {'size': fileSize},
    'maxAccess': ?maxAccess,
    'hideEmail': hideEmail,
    'disabled': disabled,
    'expiresAt': ?_seconds(expiresAt),
    'deletionAt': _seconds(deletionAt),
    if (password != null) 'password': sendProofText(password!),
  };
}

/// What `PUT /sends/{id}` takes. The server replaces every option, so all are sent again.
class KmSendUpdate {
  const KmSendUpdate({
    required this.meta,
    required this.deletionAt,
    this.payload,
    this.maxAccess,
    this.hideEmail = false,
    this.disabled = false,
    this.expiresAt,
    this.password,
    this.removePassword = false,
  }) : assert(password == null || !removePassword, 'a new password or none, not both');

  final Uint8List meta;

  /// New content, for a text Send; null keeps it.
  final Uint8List? payload;
  final int? maxAccess;
  final bool hideEmail;
  final bool disabled;
  final DateTime? expiresAt;
  final DateTime deletionAt;

  /// A new password proof, 32 bytes; null keeps the password.
  final Uint8List? password;

  /// Takes the password away.
  final bool removePassword;

  Map<String, Object?> toJson() => {
    'meta': b64urlEncode(meta),
    if (payload != null) 'payload': b64urlEncode(payload!),
    'maxAccess': ?maxAccess,
    'hideEmail': hideEmail,
    'disabled': disabled,
    'expiresAt': ?_seconds(expiresAt),
    'deletionAt': _seconds(deletionAt),
    if (password != null) 'password': sendProofText(password!),
    if (removePassword) 'removePassword': true,
  };
}

/// The Send routes over [api].
class KmSendsApi {
  const KmSendsApi(this.api);

  final KmApi api;

  /// What an access answer may hold: a 256 KiB payload in base64url, with room.
  static const maxAccessBytes = 512 * 1024;

  /// What a problem answer may hold, and the least a download's read is allowed, so a refusal of a small file isn't
  /// mistaken for a file that is too long. The upload's answer is a whole `SendDto`, whose 16 KiB of sealed meta
  /// alone is 21 KiB of base64url, so it is read up to [KmApi.maxJsonBytes] like the other owner's answers.
  static const _problemRoom = 16 * 1024;

  // ─── The owner's routes ────────────────────────────────────────────────

  /// `POST /sends`: makes a Send. A file Send is closed until its bytes arrive ([upload]).
  Future<KmSend> create(Uri server, String token, KmNewSend send) => _owner(() async {
    final answer = await api.callBytes('POST', server, '/sends', token: token, body: send.toJson());
    return KmSend.fromJson(_json(answer));
  });

  /// `GET /sends`: the account's Sends, newest first. The Bitwarden API keeps its Sends in the same table, and this
  /// list returns them too, with a `sealedKey` that is the UTF-8 of Bitwarden's encrypted key string and never 64
  /// bytes. They come back as [KmForeignSend]s: no Kemlock link opens them and nothing of them is decrypted. Any other
  /// Send that can't be read, a `sealedKey` that isn't base64url included, is a `server` [KmError], so the page shows
  /// none rather than half.
  Future<List<KmListedSend>> list(Uri server, String token) => _owner(() async {
    final answer = await api.callBytes('GET', server, '/sends', token: token, maxBytes: KmApi.maxPageBytes);
    final json = _json(answer);
    if (json is! List<Object?>) throw const FormatException('the list of Sends is a list');
    return <KmListedSend>[
      for (final send in json)
        if (!_isBitwardens(send)) KmSend.fromJson(send) else ?_foreignOrNull(send),
    ];
  });

  /// A Bitwarden app's Send, or null when the server lists it in a shape this app doesn't read: the Bitwarden API owns
  /// those rows, so one that doesn't read is left out rather than failing the account's whole list of its own Sends.
  static KmForeignSend? _foreignOrNull(Object? json) {
    try {
      return KmForeignSend.fromJson(json);
    } on Exception {
      return null;
    }
  }

  /// Whether [json] is a Send of the Bitwarden API: its `sealedKey` decodes to a length other than the 64 bytes the
  /// Kemlock routes make the server check, so a Kemlock Send never has one. A `sealedKey` that isn't base64url is
  /// neither, and [KmSend.fromJson] refuses it.
  static bool _isBitwardens(Object? json) {
    if (json is! Map<String, Object?>) return false;
    final key = json['sealedKey'];
    if (key is! String) return false;
    try {
      return b64urlDecode(key).length != sendSealedKeyLength;
    } on MalformedException {
      return false;
    }
  }

  /// `GET /sends/{id}`.
  Future<KmSend> get(Uri server, String token, String id) => _owner(() async {
    return KmSend.fromJson(_json(await api.callBytes('GET', server, '/sends/$id', token: token)));
  });

  /// `PUT /sends/{id}`: changes a Send's options, meta, text and password. Its key, file and open count never change.
  Future<KmSend> update(Uri server, String token, String id, KmSendUpdate update) => _owner(() async {
    final answer = await api.callBytes('PUT', server, '/sends/$id', token: token, body: update.toJson());
    return KmSend.fromJson(_json(answer));
  });

  /// `DELETE /sends/{id}`, a file's bytes included. A Send that is gone already counts as deleted.
  Future<void> delete(Uri server, String token, String id) async {
    try {
      await api.callBytes('DELETE', server, '/sends/$id', token: token);
    } on KmError catch (e) {
      final failure = sendsFailure(e);
      if (failure is SendsError && failure.problem == SendsProblem.notFound) return;
      throw failure;
    }
  }

  /// `PUT /sends/{id}/file`: the `KMA1` [bytes] of a file Send, with their `Content-Length`. [uploadUrl] is what the
  /// server answered when it made the Send, and must be on the server's own host: the bytes go to its own route and
  /// carry the token and a proof, as no other host should see them.
  Future<KmSend> upload(Uri server, String token, String id, String uploadUrl, Uint8List bytes) => _owner(() async {
    if (!kmSameServer(server, uploadUrl)) throw const KmError(KmProblem.server, message: 'the upload address is another host');
    final answer = await api.callBytes('PUT', server, '/sends/$id/file', token: token, bytes: bytes, timeout: api.fileTimeout);
    return KmSend.fromJson(_json(answer));
  });

  // ─── The public routes of a link ───────────────────────────────────────

  /// `POST /send-access/{accessId}` on [server], the link's own address with its path: opens a Send. No token and no
  /// proof of device go with it, whoever asks. [password] is the Argon2id proof of the password, which the request
  /// carries as `password`; null sends no body. A text Send counts an open here.
  Future<KmSendAccess> access(Uri server, String accessId, {Uint8List? password}) async {
    try {
      final answer = await api.callBytes(
        'POST',
        server,
        '/send-access/$accessId',
        body: password == null ? null : {'password': sendProofText(password)},
        proof: false,
        maxBytes: maxAccessBytes,
      );
      return KmSendAccess.fromJson(_json(answer));
    } on KmError catch (e) {
      throw sendsFailure(e);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: 'a Send answer: ${e.message}');
    }
  }

  /// `POST /send-access/{accessId}/file`: a file Send's bytes, which count as an open. Never more than [fileSize] are
  /// kept: an answer that promises or sends more is dropped, and a file of another length than [fileSize] is a
  /// `server` [KmError]. [fileSize] is the `KMA1` length the access answer named.
  Future<Uint8List> download(Uri server, String accessId, {required int fileSize, Uint8List? password}) async {
    try {
      final bytes = await api.callBytes(
        'POST',
        server,
        '/send-access/$accessId/file',
        body: password == null ? null : {'password': sendProofText(password)},
        proof: false,
        maxBytes: math.max(fileSize, _problemRoom),
        timeout: api.fileTimeout,
        accept: 'application/octet-stream',
      );
      if (bytes.length != fileSize) throw const KmError(KmProblem.server, message: 'the file is not the length the Send named');
      return bytes;
    } on KmError catch (e) {
      throw sendsFailure(e);
    }
  }

  Future<T> _owner<T>(Future<T> Function() request) async {
    try {
      return await request();
    } on KmError catch (e) {
      throw sendsFailure(e);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: 'a Send answer: ${e.message}');
    }
  }

  Object? _json(Uint8List bytes) => jsonDecode(utf8.decode(bytes));
}
