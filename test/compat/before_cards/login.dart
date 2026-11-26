// A frozen copy of lib/models/login.dart as it was at 7ee88deb, before
// website rules (the add-cards-identities-and-websites plan): what a phone that
// stays on the previous version runs. It reads `websites` alone, keeps `uris`
// in `extra` and writes it back, as every key it does not know. Tests edit
// with it, as such a phone does. Never update it.
import 'package:kemlock_core/models/item_link.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/vault_entry.dart';

/// The most previous passwords a login keeps, newest first.
const previousPasswordsKept = 5;

/// A password a login had before, and when it was replaced (epoch ms).
class PreviousPassword {
  const PreviousPassword({required this.password, required this.until, this.extra = const {}});

  factory PreviousPassword.fromJson(Map<String, Object?> json) => PreviousPassword(
    password: asString(json['password']),
    until: asInt(json['until']) ?? 0,
    extra: extraKeys(json, const {'password', 'until'}),
  );

  final String password;
  final int until;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'password': password, 'until': until, ...extra};

  @override
  bool operator ==(Object other) => other is PreviousPassword && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(password, until);

  @override
  String toString() => 'PreviousPassword(until: $until)';
}

/// A site's sign-in kept in the vault (openspec: logins): a name, the
/// username and the password, the websites AutoFill fills it on, and an
/// optional link to the OTP account holding its code. Keys it doesn't know
/// are kept in [extra] and written back, as on every model.
class Login implements VaultEntry<Login> {
  const Login({
    required this.id,
    required this.name,
    this.username,
    this.password,
    this.websites,
    this.note,
    this.tags,
    this.pinned,
    this.spaceId,
    this.accountId,
    this.passwordChangedAt,
    this.previousPasswords,
    this.codeWarning,
    this.source,
    required this.addedAt,
    this.updatedAt,
    this.extra = const {},
  });

  factory Login.fromJson(Map<String, Object?> json) => Login(
    id: asString(json['id']),
    name: asString(json['name']),
    username: asOptionalString(json['username']),
    password: asOptionalString(json['password']),
    websites: asStrings(json['websites']),
    note: asOptionalString(json['note']),
    tags: asStrings(json['tags']),
    pinned: asBool(json['pinned']),
    spaceId: asOptionalString(json['spaceId']),
    accountId: asOptionalString(json['accountId']),
    passwordChangedAt: asInt(json['passwordChangedAt']),
    previousPasswords: switch (json['previousPasswords']) {
      final List<Object?> list => [
        for (final item in list)
          if (item is Map<String, Object?>) PreviousPassword.fromJson(item),
      ],
      _ => null,
    },
    codeWarning: asBool(json['codeWarning']),
    source: asOptionalString(json['source']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    extra: extraKeys(json, _keys),
  );

  static const _keys = {
    'id',
    'name',
    'username',
    'password',
    'websites',
    'note',
    'tags',
    'pinned',
    'spaceId',
    'accountId',
    'passwordChangedAt',
    'previousPasswords',
    'codeWarning',
    'source',
    'addedAt',
    'updatedAt',
  };

  /// What [source] is for a login AutoFill saved.
  static const fromAutofill = 'autofill';

  @override
  final String id;

  /// What the person calls it: "Larkspur Mail".
  final String name;
  final String? username;
  final String? password;

  /// The hosts it is filled on (`normaliseWebsite`), and their subdomains under the domain each is under.
  final List<String>? websites;
  final String? note;
  final List<String>? tags;

  /// Shown first in the list.
  final bool? pinned;

  /// The shared space this login belongs to; absent for the vault's own.
  @override
  final String? spaceId;

  /// The id of the OTP account of the same vault holding this login's code.
  final String? accountId;

  /// Epoch ms the password last changed.
  final int? passwordChangedAt;

  /// The passwords it had before, newest first, at most [previousPasswordsKept].
  final List<PreviousPassword>? previousPasswords;

  /// False once the person asked not to be warned that its site offers a code and none is linked.
  final bool? codeWarning;

  /// [fromAutofill] for a login AutoFill saved.
  final String? source;

  /// Epoch ms the login was added.
  final int addedAt;

  /// Epoch ms of the last change, so sync can tell which copy is newer.
  final int? updatedAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get isPinned => pinned ?? false;

  /// A login needs a name and a username or a password.
  bool get isComplete => name.trim().isNotEmpty && ((username?.isNotEmpty ?? false) || (password?.isNotEmpty ?? false));

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'username': ?username,
    'password': ?password,
    if (websites?.isNotEmpty ?? false) 'websites': websites,
    'note': ?note,
    'tags': ?tags,
    'pinned': ?pinned,
    'spaceId': ?spaceId,
    'accountId': ?accountId,
    'passwordChangedAt': ?passwordChangedAt,
    if (previousPasswords?.isNotEmpty ?? false) 'previousPasswords': [for (final previous in previousPasswords!) previous.toJson()],
    'codeWarning': ?codeWarning,
    'source': ?source,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  Login copyWith({
    String? id,
    String? name,
    Object? username = keep,
    Object? password = keep,
    Object? websites = keep,
    Object? note = keep,
    Object? tags = keep,
    Object? pinned = keep,
    Object? spaceId = keep,
    Object? accountId = keep,
    Object? passwordChangedAt = keep,
    Object? previousPasswords = keep,
    Object? codeWarning = keep,
    Object? source = keep,
    int? addedAt,
    Object? updatedAt = keep,
  }) => Login(
    id: id ?? this.id,
    name: name ?? this.name,
    username: pick(username, this.username),
    password: pick(password, this.password),
    websites: pick(websites, this.websites),
    note: pick(note, this.note),
    tags: pick(tags, this.tags),
    pinned: pick(pinned, this.pinned),
    spaceId: pick(spaceId, this.spaceId),
    accountId: pick(accountId, this.accountId),
    passwordChangedAt: pick(passwordChangedAt, this.passwordChangedAt),
    previousPasswords: pick(previousPasswords, this.previousPasswords),
    codeWarning: pick(codeWarning, this.codeWarning),
    source: pick(source, this.source),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    extra: extra,
  );

  /// A copy that keeps [old] among the previous passwords as replaced [until],
  /// newest first and at most [previousPasswordsKept], unless [old] is empty,
  /// the password now, or already kept.
  Login keepingPrevious(String old, int until) {
    final kept = previousPasswords ?? const <PreviousPassword>[];
    if (old.isEmpty || old == password || kept.any((p) => p.password == old)) return this;
    final all = [...kept, PreviousPassword(password: old, until: until)]..sort((a, b) => b.until.compareTo(a.until));
    return copyWith(previousPasswords: all.take(previousPasswordsKept).toList());
  }

  /// A copy whose password is [next], changed [at]: the password it replaces
  /// is kept among the previous passwords, and [next] leaves them if it was
  /// one of them. The same password changes nothing.
  Login withPassword(String? next, int at) {
    final value = next == null || next.isEmpty ? null : next;
    if (value == password) return this;
    final rest = [...?previousPasswords]..removeWhere((p) => p.password == value);
    final changed = copyWith(password: value ?? unset, passwordChangedAt: at, previousPasswords: rest.isEmpty ? unset : rest);
    return password == null ? changed : changed.keepingPrevious(password!, at);
  }

  @override
  bool operator ==(Object other) => other is Login && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  @override
  Login stamped(int at) => copyWith(updatedAt: at);

  @override
  Login inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  // Added only so the frozen copy still implements VaultEntry, which gained links in the item-format port:
  // a phone of this version keeps a body's `links` in [extra] and knows none of its own.
  @override
  List<ItemLink> get links => const [];

  @override
  Login withLinks(List<ItemLink> links) => this;

  /// Never the username or the password, which logs and test failures would show.
  @override
  String toString() => 'Login($id, $name)';
}
