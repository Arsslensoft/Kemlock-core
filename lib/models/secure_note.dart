import 'json.dart';
import 'vault_entry.dart';

/// The longest text a note may hold. It keeps the vault's note list small
/// enough for preferences, and fits a Bitwarden secure note.
const noteTextLimit = 10000;

/// The largest file a note may hold, in bytes: a phone reads a picked file
/// into memory before it is encrypted.
const attachmentSizeLimit = 50 * 1024 * 1024;

/// The most files one note may hold.
const attachmentsPerNote = 100;

/// A file attached to a note. The file itself is stored encrypted, apart
/// from the vault (`KMA1`, see `attachment_format.dart`), under its [id];
/// this record is all that says what it is, and the [key] that opens it.
class NoteAttachment {
  const NoteAttachment({
    required this.id,
    required this.name,
    required this.size,
    this.type,
    required this.key,
    required this.addedAt,
    this.extra = const {},
  });

  factory NoteAttachment.fromJson(Map<String, Object?> json) => NoteAttachment(
    id: asString(json['id']),
    name: asString(json['name']),
    size: asInt(json['size']) ?? 0,
    type: asOptionalString(json['type']),
    key: asString(json['key']),
    addedAt: asInt(json['addedAt']) ?? 0,
    extra: extraKeys(json, const {'id', 'name', 'size', 'type', 'key', 'addedAt'}),
  );

  /// 16 random bytes in base64url; also the stored file's name.
  final String id;

  /// The file's name as it was attached.
  final String name;

  /// The file's size in bytes, before encryption.
  final int size;

  /// Its media type, when the picker knew it.
  final String? type;

  /// The file's own 256-bit AES key, base64.
  final String key;

  /// Epoch ms the file was attached.
  final int addedAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'id': id, 'name': name, 'size': size, 'type': ?type, 'key': key, 'addedAt': addedAt, ...extra};

  @override
  bool operator ==(Object other) => other is NoteAttachment && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() => 'NoteAttachment($id, $name, $size)';
}

/// What a note that keeps a security key's PIV management key holds for
/// Kemlock to find it again (openspec: add-piv-management, design decision
/// 10): which security key it is for, the key's kind and the key itself.
/// The person reads the same in the note's text, which they may edit.
class NotePivKey {
  const NotePivKey({required this.key, required this.algorithm, required this.managementKey, this.extra = const {}});

  /// The object under a note's `piv`, or null when it is not one this
  /// version reads, which the note then keeps as it was.
  static NotePivKey? tryParse(Object? json) {
    if (json is! Map<String, Object?>) return null;
    final key = json['key'];
    final algorithm = json['algorithm'];
    final managementKey = json['managementKey'];
    if (key is! String || algorithm is! String || managementKey is! String) return null;
    return NotePivKey(
      key: key,
      algorithm: algorithm,
      managementKey: managementKey,
      extra: extraKeys(json, const {'key', 'algorithm', 'managementKey'}),
    );
  }

  /// The security key's serial number, or its card identifier.
  final String key;

  /// `aes256` or `3des`.
  final String algorithm;

  /// The management key in hex.
  final String managementKey;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'key': key, 'algorithm': algorithm, 'managementKey': managementKey, ...extra};

  @override
  bool operator ==(Object other) => other is NotePivKey && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => key.hashCode;
}

/// A note in the vault: a title, free text, and attached files. Keys it
/// doesn't know are kept in [extra] and written back.
class SecureNote implements VaultEntry<SecureNote> {
  const SecureNote({
    required this.id,
    required this.title,
    this.text = '',
    this.tags,
    this.pinned,
    this.spaceId,
    required this.addedAt,
    this.updatedAt,
    this.attachments,
    this.piv,
    this.extra = const {},
  });

  factory SecureNote.fromJson(Map<String, Object?> json) {
    final piv = NotePivKey.tryParse(json['piv']);
    return SecureNote(
      id: asString(json['id']),
      title: asString(json['title']),
      text: asString(json['text']),
      tags: json['tags'] is List ? (json['tags']! as List<Object?>).whereType<String>().toList() : null,
      pinned: asBool(json['pinned']),
      spaceId: asOptionalString(json['spaceId']),
      addedAt: asInt(json['addedAt']) ?? 0,
      updatedAt: asInt(json['updatedAt']),
      attachments: json['attachments'] is List
          ? [for (final file in (json['attachments']! as List<Object?>).whereType<Map<String, Object?>>()) NoteAttachment.fromJson(file)]
          : null,
      piv: piv,
      // A piv this version can't read stays among the keys it doesn't know.
      extra: extraKeys(json, {
        'id',
        'title',
        'text',
        'tags',
        'pinned',
        'spaceId',
        'addedAt',
        'updatedAt',
        'attachments',
        if (piv != null) 'piv',
      }),
    );
  }

  @override
  final String id;
  final String title;
  final String text;
  final List<String>? tags;
  final bool? pinned;

  @override
  final String? spaceId;

  /// Epoch ms the note was added.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// Absent on a note that never had a file.
  final List<NoteAttachment>? attachments;

  /// Present only on a note Kemlock made to keep a security key's
  /// management key.
  final NotePivKey? piv;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// The attached files, none when [attachments] is absent.
  List<NoteAttachment> get files => attachments ?? const [];

  bool get isPinned => pinned ?? false;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'title': title,
    'text': text,
    'tags': ?tags,
    'pinned': ?pinned,
    'spaceId': ?spaceId,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    if (attachments case final files?) 'attachments': [for (final file in files) file.toJson()],
    if (piv case final piv?) 'piv': piv.toJson(),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  SecureNote copyWith({
    String? id,
    String? title,
    String? text,
    Object? tags = keep,
    Object? pinned = keep,
    Object? spaceId = keep,
    int? addedAt,
    Object? updatedAt = keep,
    Object? attachments = keep,
    Object? piv = keep,
  }) => SecureNote(
    id: id ?? this.id,
    title: title ?? this.title,
    text: text ?? this.text,
    tags: pick(tags, this.tags),
    pinned: pick(pinned, this.pinned),
    spaceId: pick(spaceId, this.spaceId),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    attachments: pick(attachments, this.attachments),
    piv: pick(piv, this.piv),
    // A piv given here takes the place of one this version could not read.
    extra: identical(piv, keep) || !extra.containsKey('piv') ? extra : ({...extra}..remove('piv')),
  );

  @override
  int get changedAt => updatedAt ?? addedAt;

  @override
  SecureNote stamped(int at) => copyWith(updatedAt: at);

  @override
  SecureNote inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  @override
  bool operator ==(Object other) => other is SecureNote && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  /// Never the text, the files' keys or a PIV management key: what prints
  /// can end up in a log.
  @override
  String toString() => 'SecureNote($id, $title, ${files.length} files)';
}
