import 'dart:async';
import 'dart:convert';
import 'dart:math';

import '../core/storage/key_value_store.dart';

/// The first vault's id. Its keys are the ones every earlier version used.
const mainVault = 'main';

/// Each vault's config; one per vault, so the keys holding it list the vaults.
const keyConfig = 'backmycodes_vault_config';

/// The language, which belongs to the device and survives a reset.
const keyLocale = 'backmycodes_locale';

/// The look chosen in Settings, which belongs to the device and survives a
/// reset, as MUI's colour-scheme mode in the WebView's own storage did.
const keyTheme = 'backmycodes_theme';

const _keyRegistry = 'backmycodes_vaults';
const _keyLast = 'backmycodes_last_vault';

/// The wrong master passwords typed on the lock screen while it lists no
/// vault, which count for the phone (`unlock_attempts.dart`).
const keyUnlockFailuresDevice = 'backmycodes_unlock_failures_device';

/// Erasing every vault after wrong passwords, `{"after": 10 | 15 | 20}`,
/// absent while it is off (`unlock_attempts.dart`).
const keyUnlockErase = 'backmycodes_unlock_erase';

/// That every vault was erased after wrong passwords, `{"at": ms, "after": n}`,
/// for the setup screen to say until a vault is made.
const keyErased = 'backmycodes_erased';

/// An erase of every vault under way ([VaultRegistry.removeAllVaults]):
/// written before the first key goes and deleted after the last, so one
/// found at launch was cut short, and [VaultRegistry.finishCutShortErase]
/// finishes it. Its value is the note for [keyErased], or empty.
const keyErasing = 'backmycodes_erasing';

/// The key reminders each listed vault has scheduled: by vault id, each notification id with
/// the date, days left, count and language it was scheduled for, so one vault's can be
/// cancelled while another is open (`key_reminders.dart`). A hidden vault is never in it.
const keyKeyReminders = 'backmycodes_key_reminders';

/// Offline mode, `{"on": true}`, absent while it is off (`platform/network.dart`). It is the
/// phone's, and a reset keeps it: erasing the vaults is not asking for the network back.
const keyOffline = 'backmycodes_offline';

/// The device keys a reset keeps.
const _keptOnReset = {keyLocale, keyTheme, keyOffline};

/// Keys that belong to the device rather than to one vault. Two are the breach list the
/// online update stored and when it last checked (`breach_refresh.dart`); three count and
/// act on wrong passwords for the phone as a whole; the last is the scheduled key reminders.
const _deviceKeys = {
  _keyRegistry,
  _keyLast,
  keyLocale,
  keyTheme,
  'backmycodes_breach_list',
  'backmycodes_breach_check',
  // The password generator's last choices (generator_sheet.dart), for every vault of the phone
  'backmycodes_generator',
  keyUnlockFailuresDevice,
  keyUnlockErase,
  keyErased,
  keyErasing,
  keyKeyReminders,
  keyOffline,
};
const _sep = '::';

final _random = Random.secure();

/// Several vaults on one device, each with its own password,
/// accounts, backups and settings, as `vaults.ts` keeps them.
///
/// The first vault keeps the storage keys every earlier version used, so
/// existing vaults need no migration; another vault stores the same keys
/// with `::<id>` appended. The registry lists the vaults the lock screen
/// offers. A hidden vault is simply not listed: it opens when its password
/// is typed on the lock screen. That keeps it from someone looking at the
/// app, not from someone reading the device's storage.
class VaultRegistry {
  VaultRegistry(this._store);

  final KeyValueStore _store;
  String _active = mainVault;
  final List<void Function()> _listeners = [];

  /// The vault being unlocked or used; storage reads and writes go to it.
  String get active => _active;

  set active(String id) {
    if (id == _active) return;
    _active = id;
    // Not synchronously: the lock screen picks its vault while building, and
    // rebuilding another widget in the middle of that is an error.
    scheduleMicrotask(() {
      for (final listener in [..._listeners]) {
        listener();
      }
    });
  }

  /// Calls [onChange] after the active vault changes; returns the call that stops it.
  void Function() listen(void Function() onChange) {
    _listeners.add(onChange);
    return () => _listeners.remove(onChange);
  }

  /// The storage key for [base] in a vault, the active one unless another is given.
  String vaultKey(String base, [String? id]) {
    final vault = id ?? _active;
    return vault == mainVault ? base : '$base$_sep$vault';
  }

  /// Every vault on the device, listed or hidden, the first vault first.
  List<String> allVaultIds() {
    final ids = <String>[];
    for (final key in _store.storedKeys()) {
      if (key == keyConfig) {
        ids.insert(0, mainVault);
      } else if (key.startsWith('$keyConfig$_sep')) {
        ids.add(key.substring(keyConfig.length + _sep.length));
      }
    }
    return ids;
  }

  List<String>? _readRegistry() {
    final raw = _store.getItem(_keyRegistry);
    if (raw == null) return null;
    try {
      final parsed = jsonDecode(raw);
      final listed = parsed is Map ? parsed['listed'] : null;
      return listed is List ? listed.whereType<String>().toList() : [];
    } catch (_) {
      return null;
    }
  }

  /// Vaults the lock screen offers. Before any second vault existed, that's the first one.
  List<String> listedVaultIds() {
    final all = allVaultIds();
    final registry = _readRegistry();
    if (registry == null) return all.contains(mainVault) ? [mainVault] : [];
    return registry.where(all.contains).toList();
  }

  List<String> hiddenVaultIds() {
    final listed = listedVaultIds().toSet();
    return allVaultIds().where((id) => !listed.contains(id)).toList();
  }

  bool isListed(String id) => listedVaultIds().contains(id);

  /// Shows a vault on the lock screen or hides it.
  void setListed(String id, bool listed) {
    final current = listedVaultIds().where((x) => x != id).toList();
    _store.setItem(
      _keyRegistry,
      jsonEncode({
        'listed': [...current, if (listed) id],
      }),
    );
    if (!listed && _store.getItem(_keyLast) == id) _store.removeItem(_keyLast);
  }

  /// The listed vault the lock screen starts on: the last one opened, else the first.
  String? startingVault() {
    final listed = listedVaultIds();
    final last = _store.getItem(_keyLast);
    return last != null && listed.contains(last) ? last : listed.firstOrNull;
  }

  /// Remembers the vault for next time, unless it's hidden; a hidden one is never written down.
  void rememberVault(String id) {
    if (isListed(id)) _store.setItem(_keyLast, id);
  }

  /// The name a vault was given, or null for the first vault, which has none until renamed.
  String? vaultName(String id) {
    try {
      final raw = _store.getItem(vaultKey(keyConfig, id));
      final name = raw == null ? null : (jsonDecode(raw) as Map<String, Object?>)['name'];
      return name is String && name.trim().isNotEmpty ? name : null;
    } catch (_) {
      return null;
    }
  }

  /// A new vault's id: six random bytes in hex.
  static String newVaultId() => List.generate(6, (_) => _random.nextInt(256).toRadixString(16).padLeft(2, '0')).join();

  bool _isVaultKey(String key, String id) {
    if (id != mainVault) return key.endsWith('$_sep$id');
    return !key.contains(_sep) && !_deviceKeys.contains(key);
  }

  /// Every stored key of one vault, those a newer version wrote included,
  /// and none of the device's or another vault's.
  List<String> keysOf(String id) => [
    for (final key in _store.storedKeys())
      if (_isVaultKey(key, id)) key,
  ];

  /// Deletes one vault's data and its place on the lock screen.
  void removeVaultData(String id) {
    keysOf(id).forEach(_store.removeItem);
    if (_readRegistry() != null || id == mainVault) setListed(id, false);
    if (_active == id) active = mainVault;
  }

  /// Deletes every vault on the device; only the language, the look and offline mode survive. With [erasedNote], it
  /// is left under [keyErased] for setup.
  ///
  /// The keys go one by one, so [keyErasing] goes in first and out last. The phone's storage
  /// gets the writes in the order they are made, each once the one before it is done, so the
  /// mark is stored before the first key goes: an erase the app is killed in the middle of
  /// leaves it beside the keys it hadn't deleted yet, the erase setting perhaps among those
  /// gone, and the next launch finishes it ([finishCutShortErase]) before any vault opens.
  void removeAllVaults({String? erasedNote}) {
    _store.setItem(keyErasing, erasedNote ?? '');
    for (final key in _store.storedKeys()) {
      if (key != keyErasing && !_keptOnReset.contains(key)) _store.removeItem(key);
    }
    if (erasedNote != null) _store.setItem(keyErased, erasedNote);
    _store.removeItem(keyErasing);
    active = mainVault;
  }

  /// Finishes an erase of every vault that the app was killed in the middle of, which left
  /// [keyErasing], with the note it was to leave; true when there was one. Run at launch,
  /// before anything reads a vault.
  bool finishCutShortErase() {
    final note = _store.getItem(keyErasing);
    if (note == null) return false;
    removeAllVaults(erasedNote: note.isEmpty ? null : note);
    return true;
  }
}
