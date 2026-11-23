// Pure Dart: what KeyValueStore needs of the phone's storage, and a memory version of it.

/// Where the key-value store keeps its strings on the phone.
abstract interface class PreferencesBackend {
  /// Every string value, by key.
  Future<Map<String, String>> readAll();

  Future<void> set(String key, String value);

  Future<void> remove(String key);
}

/// Preferences in memory, for tests and where no phone storage exists.
class MemoryPreferences implements PreferencesBackend {
  MemoryPreferences([Map<String, String> values = const {}]) : values = {...values};

  /// What is "on the phone", for tests to look at.
  final Map<String, String> values;

  /// When set, the next write throws it, as a full disk would.
  Object? failNextWrite;

  /// The writes in the order they reached storage, as `set key=value` and `remove key`.
  final List<String> log = [];

  @override
  Future<Map<String, String>> readAll() async => {...values};

  @override
  Future<void> set(String key, String value) async {
    _maybeFail();
    log.add('set $key=$value');
    values[key] = value;
  }

  @override
  Future<void> remove(String key) async {
    _maybeFail();
    log.add('remove $key');
    values.remove(key);
  }

  void _maybeFail() {
    final error = failNextWrite;
    if (error == null) return;
    failNextWrite = null;
    throw error;
  }
}
