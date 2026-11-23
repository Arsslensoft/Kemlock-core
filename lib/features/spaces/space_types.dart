// The vocabulary of a space's chain and its state (the space chain section of docs/crypto.md,
// "Values"): roles, Custom permissions, collection permissions and what they give together, who a
// grant is for, which key a seal or a replacement is for and what a name names.
//
// Roles, permissions and the rules between them are the server's own (kemlock-domain's spaces.rs):
// Owner, Admin, Custom and Member, three Custom permissions, and five permissions on a collection
// grant.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/encoding.dart';
import '../../crypto/bytes.dart' show concatBytes;

/// A member's role in a space.
enum SpaceRole {
  owner('owner'),
  admin('admin'),
  custom('custom'),
  member('member');

  const SpaceRole(this.wire);

  final String wire;

  static SpaceRole? fromWire(String text) {
    for (final role in values) {
      if (role.wire == text) {
        return role;
      }
    }
    return null;
  }
}

/// What a Custom member may do, as the server's three.
enum CustomPermission {
  /// Invite, confirm, revoke and remove members and other Custom members.
  manageUsers('manage-users'),

  /// Create, change and delete groups.
  manageGroups('manage-groups'),

  /// Create collections.
  createCollections('create-collections');

  const CustomPermission(this.wire);

  final String wire;

  static CustomPermission? fromWire(String text) {
    for (final permission in values) {
      if (permission.wire == text) {
        return permission;
      }
    }
    return null;
  }
}

/// What a grant lets a member or group do with one collection's items.
enum CollectionPermission {
  view('view', canEdit: false, hidesPasswords: false, canManage: false),
  viewHidePasswords('view-hide-passwords', canEdit: false, hidesPasswords: true, canManage: false),
  edit('edit', canEdit: true, hidesPasswords: false, canManage: false),
  editHidePasswords('edit-hide-passwords', canEdit: true, hidesPasswords: true, canManage: false),
  manage('manage', canEdit: true, hidesPasswords: false, canManage: true);

  const CollectionPermission(this.wire, {required this.canEdit, required this.hidesPasswords, required this.canManage});

  final String wire;
  final bool canEdit;

  /// A display rule only: the member holds the key, so it guards against shoulder-surfing and careless copying,
  /// not against the member.
  final bool hidesPasswords;

  /// May grant this collection, and no other.
  final bool canManage;

  static CollectionPermission? fromWire(String text) {
    for (final permission in values) {
      if (permission.wire == text) {
        return permission;
      }
    }
    return null;
  }
}

/// The rights grants give together: the more permissive wins on every count, so passwords stay hidden only
/// when every grant hides them.
final class Access {
  const Access({required this.edit, required this.hidePasswords, required this.manage});

  Access.of(CollectionPermission permission)
    : this(edit: permission.canEdit, hidePasswords: permission.hidesPasswords, manage: permission.canManage);

  final bool edit;
  final bool hidePasswords;
  final bool manage;

  Access combine(Access other) =>
      Access(edit: edit || other.edit, hidePasswords: hidePasswords && other.hidePasswords, manage: manage || other.manage);

  @override
  bool operator ==(Object other) => other is Access && other.edit == edit && other.hidePasswords == hidePasswords && other.manage == manage;

  @override
  int get hashCode => Object.hash(edit, hidePasswords, manage);

  @override
  String toString() => 'Access(edit: $edit, hidePasswords: $hidePasswords, manage: $manage)';
}

/// Who a grant is for: `user:<uuid>` or `group:<uuid>`.
final class Grantee {
  const Grantee.user(this.id) : isGroup = false;

  const Grantee.group(this.id) : isGroup = true;

  /// Reads `user:<uuid>` or `group:<uuid>`, hyphenated lower case.
  factory Grantee.parse(String text) {
    if (text.startsWith('user:') && isUuidText(text.substring(5))) {
      return Grantee.user(text.substring(5));
    }
    if (text.startsWith('group:') && isUuidText(text.substring(6))) {
      return Grantee.group(text.substring(6));
    }
    throw MalformedException('a grantee is user:<uuid> or group:<uuid>: $text');
  }

  final String id;
  final bool isGroup;

  String get wire => '${isGroup ? 'group' : 'user'}:$id';

  @override
  bool operator ==(Object other) => other is Grantee && other.id == id && other.isGroup == isGroup;

  @override
  int get hashCode => Object.hash(id, isGroup);

  @override
  String toString() => wire;
}

/// The rank of [role]: `owner` above `admin` above `custom` above `member`.
int roleRank(SpaceRole role) => switch (role) {
  SpaceRole.owner => 3,
  SpaceRole.admin => 2,
  SpaceRole.custom => 1,
  SpaceRole.member => 0,
};

/// Whether [after] gives a right [before] doesn't: `edit` or `manage`, no longer hiding passwords, or access where
/// there was none. Null is no access.
bool accessWidens(Access? before, Access? after) {
  if (after == null) {
    return false;
  }
  if (before == null) {
    return true;
  }
  return (after.edit && !before.edit) || (after.manage && !before.manage) || (before.hidePasswords && !after.hidePasswords);
}

/// A key of a space: the space key, or one collection's key. The text form is `space` or `collection:<uuid>`; in a
/// binary input it is `u8(1)`, or `u8(2) || collection id (16)`.
final class KeyRef {
  const KeyRef.space() : collection = null;

  const KeyRef.collection(String this.collection);

  /// Reads `space` or `collection:<uuid>`.
  factory KeyRef.parse(String text) {
    if (text == 'space') {
      return const KeyRef.space();
    }
    if (text.startsWith('collection:') && isUuidText(text.substring(11))) {
      return KeyRef.collection(text.substring(11));
    }
    throw MalformedException('a key is space or collection:<uuid>: $text');
  }

  /// The collection id, or null for the space key.
  final String? collection;

  bool get isSpace => collection == null;

  String get wire => collection == null ? 'space' : 'collection:$collection';

  Uint8List get bytes => collection == null ? u8(1) : concatBytes([u8(2), uuidBytes(collection!)]);

  @override
  bool operator ==(Object other) => other is KeyRef && other.collection == collection;

  @override
  int get hashCode => collection.hashCode;

  @override
  String toString() => wire;
}

/// What a name names: the space, a collection or a group. In packed names the type is `u8(1)`, `u8(2)` or `u8(3)`.
enum NameType {
  space(1, 'space'),
  collection(2, 'collection'),
  group(3, 'group');

  const NameType(this.code, this.wire);

  final int code;
  final String wire;
}

/// A name target: `space`, `collection:<uuid>` or `group:<uuid>`.
final class NameTarget {
  const NameTarget.space() : type = NameType.space, id = null;

  const NameTarget.collection(String this.id) : type = NameType.collection;

  const NameTarget.group(String this.id) : type = NameType.group;

  factory NameTarget.parse(String text) {
    if (text == 'space') {
      return const NameTarget.space();
    }
    if (text.startsWith('collection:') && isUuidText(text.substring(11))) {
      return NameTarget.collection(text.substring(11));
    }
    if (text.startsWith('group:') && isUuidText(text.substring(6))) {
      return NameTarget.group(text.substring(6));
    }
    throw MalformedException('a name target is space, collection:<uuid> or group:<uuid>: $text');
  }

  final NameType type;

  /// The collection's or group's id, null for the space.
  final String? id;

  String get wire => id == null ? 'space' : '${type.wire}:$id';

  @override
  bool operator ==(Object other) => other is NameTarget && other.type == type && other.id == id;

  @override
  int get hashCode => Object.hash(type, id);

  @override
  String toString() => wire;
}
