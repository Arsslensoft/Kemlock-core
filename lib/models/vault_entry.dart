/// What every kind of entry in a vault shares: accounts, backup services,
/// and the kinds added after them. Sync merges, stamps and moves entries
/// between scopes through it alone, so a new kind needs no code of its own
/// there. [T] is the implementing class, so a copy keeps its type.
abstract interface class VaultEntry<T extends VaultEntry<T>> {
  String get id;

  /// Epoch ms of the last change, or of when it was added if it never changed.
  int get changedAt;

  /// The shared space the entry belongs to; null for the vault's own.
  String? get spaceId;

  /// The entry as the vault, sync files and exports hold it.
  Map<String, Object?> toJson();

  /// A copy marked as changed [at] (epoch ms).
  T stamped(int at);

  /// A copy in [scope], a space's id, or in the vault's own entries when
  /// [scope] is null or empty.
  T inSpace(String? scope);
}
