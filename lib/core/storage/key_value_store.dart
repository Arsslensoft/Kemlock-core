import 'dart:async';

import 'preferences_interface.dart';

/// Every key the app stores starts with this.
const storagePrefix = 'backmycodes_';

/// Key-value storage for the vaults and settings, as `persist.ts` kept it.
///
/// Reads are synchronous: [open] loads every `backmycodes_` key before the
/// first frame, and each write lands in memory at once and in the phone's
/// storage in the background, in order. A write that fails is logged and
/// the ones after it still run.
class KeyValueStore {
  KeyValueStore._(this._backend, this._memory, this._onSaveError);

  /// Loads what the phone holds. [onSaveError] hears each write that fails (the app passes `debugPrint` through it);
  /// without it a failed write is silent.
  static Future<KeyValueStore> open(PreferencesBackend backend, {void Function(Object error)? onSaveError}) async {
    final all = await backend.readAll();
    final memory = <String, String>{
      for (final MapEntry(:key, :value) in all.entries)
        if (key.startsWith(storagePrefix)) key: value,
    };
    return KeyValueStore._(backend, memory, onSaveError);
  }

  /// A store in memory, for tests.
  factory KeyValueStore.memory([Map<String, String> values = const {}]) => KeyValueStore._(MemoryPreferences(values), {...values}, null);

  final PreferencesBackend _backend;
  final Map<String, String> _memory;
  final void Function(Object error)? _onSaveError;
  final Map<String, List<void Function()>> _listeners = {};
  Future<void> _pending = Future.value();

  /// Writes queued and not yet done.
  var _writing = 0;

  String? getItem(String key) => _memory[key];

  void setItem(String key, String value) {
    _memory[key] = value;
    _queue(() => _backend.set(key, value));
    _notify(key);
  }

  void removeItem(String key) {
    if (_memory.remove(key) == null) return;
    _queue(() => _backend.remove(key));
    _notify(key);
  }

  /// Every stored key of this app, in the order they were first stored.
  List<String> storedKeys() => _memory.keys.toList();

  /// Resolves once every write so far has reached the phone's storage.
  Future<void> flush() => _pending;

  /// Calls [onChange] after each write to [key]; returns the call that stops it.
  void Function() listen(String key, void Function() onChange) {
    final list = _listeners.putIfAbsent(key, () => []);
    list.add(onChange);
    return () => list.remove(onChange);
  }

  void _queue(Future<void> Function() write) {
    Future<void> run() => Future.sync(write).catchError((Object error, StackTrace stack) {
      _onSaveError?.call(error);
    });
    // With nothing under way the write starts now, rather than after a chain that has finished,
    // which may belong to another zone (a test's real one) that [flush] would then wait on.
    _writing++;
    _pending = (_writing == 1 ? run() : _pending.then((_) => run())).whenComplete(() => _writing--);
  }

  void _notify(String key) {
    for (final listener in [...?_listeners[key]]) {
      listener();
    }
  }
}
