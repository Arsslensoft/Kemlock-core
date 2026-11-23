import 'json.dart';
import 'vault_entry.dart';

/// One backup code of a service.
class BackupCode {
  const BackupCode({required this.code, this.used = false, this.usedAt, this.extra = const {}});

  factory BackupCode.fromJson(Map<String, Object?> json) => BackupCode(
    code: asString(json['code']),
    used: json['used'] == true,
    usedAt: asInt(json['usedAt']),
    extra: extraKeys(json, const {'code', 'used', 'usedAt'}),
  );

  final String code;
  final bool used;

  /// Epoch ms of when the code was marked used.
  final int? usedAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'code': code, 'used': used, 'usedAt': ?usedAt, ...extra};

  BackupCode copyWith({String? code, bool? used, Object? usedAt = keep}) =>
      BackupCode(code: code ?? this.code, used: used ?? this.used, usedAt: pick(usedAt, this.usedAt), extra: extra);

  @override
  bool operator ==(Object other) => other is BackupCode && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => code.hashCode;

  /// Never the code: what prints can end up in a log.
  @override
  String toString() => 'BackupCode(used: $used)';
}

/// A service and the backup codes it gave, in the JSON the vault holds
/// (`types.ts`). Keys it doesn't know are kept in [extra] and written back.
class BackupService implements VaultEntry<BackupService> {
  const BackupService({
    required this.id,
    required this.serviceName,
    required this.codes,
    this.note,
    this.spaceId,
    required this.addedAt,
    this.updatedAt,
    this.breachesDismissed,
    this.extra = const {},
  });

  factory BackupService.fromJson(Map<String, Object?> json) => BackupService(
    id: asString(json['id']),
    serviceName: asString(json['serviceName']),
    codes: [for (final code in (json['codes'] as List<Object?>?) ?? const []) BackupCode.fromJson(code! as Map<String, Object?>)],
    note: asOptionalString(json['note']),
    spaceId: asOptionalString(json['spaceId']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    breachesDismissed: asStrings(json['breachesDismissed']),
    extra: extraKeys(json, const {'id', 'serviceName', 'codes', 'note', 'spaceId', 'addedAt', 'updatedAt', 'breachesDismissed'}),
  );

  @override
  final String id;
  final String serviceName;
  final List<BackupCode> codes;
  final String? note;

  /// The shared space this service belongs to; absent for the vault's own services.
  @override
  final String? spaceId;

  /// Epoch ms the service was added.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// The breaches of this service that were marked dealt with, by Have I Been Pwned's name
  /// for each (openspec: breach-alerts). Absent when there are none.
  final List<String>? breachesDismissed;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'serviceName': serviceName,
    'codes': [for (final code in codes) code.toJson()],
    'note': ?note,
    'spaceId': ?spaceId,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    if (breachesDismissed?.isNotEmpty ?? false) 'breachesDismissed': breachesDismissed,
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  BackupService copyWith({
    String? id,
    String? serviceName,
    List<BackupCode>? codes,
    Object? note = keep,
    Object? spaceId = keep,
    int? addedAt,
    Object? updatedAt = keep,
    Object? breachesDismissed = keep,
  }) => BackupService(
    id: id ?? this.id,
    serviceName: serviceName ?? this.serviceName,
    codes: codes ?? this.codes,
    note: pick(note, this.note),
    spaceId: pick(spaceId, this.spaceId),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    breachesDismissed: pick(breachesDismissed, this.breachesDismissed),
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is BackupService && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  @override
  BackupService stamped(int at) => copyWith(updatedAt: at);

  /// As in the TypeScript, an empty scope counts as none.
  @override
  BackupService inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  /// Never the codes, nor the note: what prints can end up in a log.
  @override
  String toString() => 'BackupService($id, $serviceName, ${codes.length} codes)';
}
