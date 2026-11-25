// What a merge keeps (the add-duplicate-cleaner plan, design 6): the fields
// that differ in a group, the value each is taken from, the item that stays,
// and the item that results. `VaultController.mergeDuplicates` saves the
// result, and the merge sheet shows the choices, so both read the same rules:
//
// - each field preselects the newest value, and any other can be picked;
// - a login keeps the union of its group's websites, with the narrower rule
//   where one address has two, and the tags;
// - no password is lost: the ones not kept go among the kept login's
//   previous passwords, the newest first, five at most;
// - a held HOTP code keeps the highest counter;
// - when the group is across places, the space's copy stays, and when the
//   person can't change it only the other copy goes.
//
// Pure Dart, no Flutter package.
library;

import '../../models/backup_service.dart';
import '../../models/contact.dart';
import '../../models/identity.dart';
import '../../models/json.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_entry.dart';
import '../../models/vault_key.dart';
import '../../models/website_rule.dart';
import 'dedup_cache.dart';
import 'dedup_tagger.dart';

/// One field of an item that a merge can take from either copy. Its [id] names the label
/// (`duplicates.field.<id>`), and [read] gives its text, null when the item has none.
final class MergeField {
  const MergeField(this.id, this.read);

  final String id;
  final String? Function(Object item) read;
}

/// The fields of [item]'s kind a person can pick between.
List<MergeField> mergeFieldsOf(Object item) => switch (item) {
  Login() => [
    MergeField('name', (item) => (item as Login).name),
    MergeField('username', (item) => (item as Login).username),
    MergeField('password', (item) => (item as Login).password),
    MergeField('note', (item) => (item as Login).note),
  ],
  OtpAccount() => [MergeField('issuer', (item) => (item as OtpAccount).issuer), MergeField('label', (item) => (item as OtpAccount).label)],
  SecureNote() => [MergeField('title', (item) => (item as SecureNote).title), MergeField('text', (item) => (item as SecureNote).text)],
  BackupService() => [MergeField('name', (item) => (item as BackupService).serviceName)],
  Passkey() => [MergeField('service', (item) => (item as Passkey).rpName), MergeField('username', (item) => (item as Passkey).userName)],
  PaymentCard() => [
    MergeField('name', (item) => (item as PaymentCard).name),
    MergeField('cardholder', (item) => (item as PaymentCard).cardholder),
  ],
  Identity() => [MergeField('name', (item) => (item as Identity).name)],
  VaultKey() => [MergeField('name', (item) => (item as VaultKey).name)],
  Contact() => [MergeField('name', (item) => (item as Contact).name)],
  _ => const [],
};

/// The choices of one merge: the group's [items], the one that stays, and the item each differing
/// field is taken from. A new value is made by [withKept] and [withPick].
final class MergeChoices {
  MergeChoices._(this.items, this.keptId, this._picks, this.readOnlySlots, this.hiddenPasswords);

  /// The choices a merge of [items], one group, starts with. [readOnlySlots] are the places whose
  /// items the person can't change (a space they only read); none today for a WebDAV space.
  ///
  /// The item that stays is the space's copy when the group is across places, the newest one
  /// otherwise.
  factory MergeChoices(List<DedupItem> items, {Set<String> readOnlySlots = const {}, Set<String> hiddenPasswords = const {}}) {
    if (items.length < 2) {
      throw ArgumentError.value(items.length, 'items', 'a merge takes two items or more');
    }
    return MergeChoices._(items, _defaultKept(items).id, const {}, readOnlySlots, hiddenPasswords);
  }

  final List<DedupItem> items;

  /// The id of the item that stays.
  final String keptId;
  final Map<String, String> _picks;

  /// The slots of the places whose items can't be changed.
  final Set<String> readOnlySlots;

  /// The ids of the logins whose password a space hides from this account. A group holding one never merges
  /// passwords: the password isn't a choice, and a hidden one never becomes a previous password of another login,
  /// where it would show.
  final Set<String> hiddenPasswords;

  bool get _passwordsHidden => items.any((item) => hiddenPasswords.contains(item.id));

  DedupItem get kept => items.firstWhere((item) => item.id == keptId);

  /// The items that go, in the order the group lists them.
  List<DedupItem> get removed => [
    for (final item in items)
      if (item.id != keptId) item,
  ];

  /// Whether the items are in more than one place.
  bool get acrossPlaces => items.map((item) => item.slot).toSet().length > 1;

  /// Whether the item that stays can't be changed, so a merge only removes the others.
  bool get keptIsReadOnly => readOnlySlots.contains(kept.slot);

  /// The fields whose text differs between the items. None when the kept item can't be changed.
  List<MergeField> get differing {
    if (keptIsReadOnly) {
      return const [];
    }
    return [
      for (final field in mergeFieldsOf(kept.item))
        if (!(field.id == 'password' && kept.item is Login && _passwordsHidden) &&
            items.map((item) => field.read(item.item) ?? '').toSet().length > 1)
          field,
    ];
  }

  /// The item [field] is taken from: the one picked, else the newest that has a value (the newest
  /// at all when none has).
  DedupItem pickFor(MergeField field) {
    final picked = _picks[field.id];
    if (picked != null) {
      final item = items.where((item) => item.id == picked);
      if (item.isNotEmpty) {
        return item.first;
      }
    }
    final withValue = items.where((item) => (field.read(item.item) ?? '').isNotEmpty).toList();
    return _newest(withValue.isEmpty ? items : withValue);
  }

  /// These choices with [field] taken from [itemId].
  MergeChoices withPick(MergeField field, String itemId) =>
      MergeChoices._(items, keptId, {..._picks, field.id: itemId}, readOnlySlots, hiddenPasswords);

  /// These choices with [itemId] staying, and every pick left to the newest again.
  MergeChoices withKept(String itemId) => MergeChoices._(items, itemId, const {}, readOnlySlots, hiddenPasswords);

  /// The item that results, made at [now] (epoch ms): the kept item with the picked fields and what
  /// the others add. It isn't stamped; the controller does that on saving.
  Object merged(int now) {
    final keptItem = kept.item;
    if (keptIsReadOnly) {
      return keptItem;
    }
    final text = {for (final field in differing) field.id: field.read(pickFor(field).item)};
    String? value(String id, String? current) => text.containsKey(id) ? text[id] : current;
    final others = [for (final item in items) item.item];
    return switch (keptItem) {
      final Login login => _mergedLogin(login, text, [for (final item in items) item.item as Login], now, hiddenPasswords),
      final OtpAccount code => _mergedCode(
        code,
        issuer: value('issuer', code.issuer) ?? '',
        label: value('label', code.label) ?? '',
        all: others.whereType<OtpAccount>().toList(),
      ),
      final SecureNote note => note.copyWith(title: value('title', note.title) ?? '', text: value('text', note.text) ?? ''),
      final BackupService service => service.copyWith(serviceName: value('name', service.serviceName) ?? ''),
      final Passkey passkey => passkey.copyWith(
        rpName: text.containsKey('service') ? text['service'] ?? unset : keep,
        userName: value('username', passkey.userName) ?? '',
      ),
      final PaymentCard card => card.copyWith(
        name: value('name', card.name) ?? '',
        cardholder: text.containsKey('cardholder') ? text['cardholder'] ?? unset : keep,
      ),
      final Identity identity => identity.copyWith(name: value('name', identity.name) ?? ''),
      final VaultKey key => key.copyWith(name: value('name', key.name) ?? ''),
      final Contact contact => contact.copyWith(name: value('name', contact.name) ?? ''),
      _ => keptItem,
    };
  }
}

DedupItem _newest(List<DedupItem> items) {
  var newest = items.first;
  for (final item in items.skip(1)) {
    if (item.changedAt > newest.changedAt) {
      newest = item;
    }
  }
  return newest;
}

/// The item that stays by default: the space's copy when the group is across places (the newest
/// of them if several), else the newest.
DedupItem _defaultKept(List<DedupItem> items) {
  if (items.map((item) => item.slot).toSet().length > 1) {
    final inSpaces = items.where((item) => (item.spaceId ?? '').isNotEmpty).toList();
    if (inSpaces.isNotEmpty) {
      return _newest(inSpaces);
    }
  }
  return _newest(items);
}

int? _highestCounter(Iterable<OtpAccount> codes) {
  final held = [
    for (final code in codes)
      if (code.kind == OtpType.hotp) code.counter ?? 0,
  ];
  return held.isEmpty ? null : held.reduce((a, b) => a > b ? a : b);
}

/// The code that results: the kept one with the picked name, the highest counter of a held HOTP code, and what the removed copies add,
/// as a login's merge keeps it: the tags, and the websites with the narrower rule where one address has two.
OtpAccount _mergedCode(OtpAccount kept, {required String issuer, required String label, required List<OtpAccount> all}) {
  final others = [
    for (final code in all)
      if (code.id != kept.id) code,
  ]..sort((a, b) => b.changedAt.compareTo(a.changedAt));
  final rules = mergeRules([kept.rules, for (final code in others) code.rules]);
  final sites = websitesOf(rules);
  final tags = <String>{...?kept.tags, for (final code in others) ...?code.tags}.toList();
  return kept.copyWith(
    issuer: issuer,
    label: label,
    counter: _highestCounter(all) ?? keep,
    tags: tags.isEmpty ? unset : tags,
    websites: sites.websites ?? unset,
    uris: sites.uris ?? unset,
  );
}

Login _mergedLogin(Login kept, Map<String, String?> text, List<Login> all, int now, Set<String> hiddenPasswords) {
  final others = [
    for (final login in all)
      if (login.id != kept.id) login,
  ]..sort((a, b) => b.changedAt.compareTo(a.changedAt));
  // The passwords the member can't read stay with their own login, and never move into another
  final readable = [
    for (final login in others)
      if (!hiddenPasswords.contains(login.id)) login,
  ];
  final password = text.containsKey('password') ? text['password'] : kept.password;
  final pickedPassword = all.firstWhere((login) => login.password == password, orElse: () => kept);
  var out = kept.copyWith(
    name: text['name'] ?? kept.name,
    username: text.containsKey('username') ? text['username'] ?? unset : keep,
    password: text.containsKey('password') ? password ?? unset : keep,
    note: text.containsKey('note') ? text['note'] ?? unset : keep,
    passwordChangedAt: text.containsKey('password') ? pickedPassword.passwordChangedAt ?? unset : keep,
  );
  final rules = mergeRules([kept.rules, for (final login in others) login.rules]);
  final sites = websitesOf(rules);
  out = out.copyWith(websites: sites.websites ?? unset, uris: sites.uris ?? unset);
  final tags = <String>{...?kept.tags, for (final login in others) ...?login.tags}.toList();
  out = out.copyWith(tags: tags.isEmpty ? unset : tags, pinned: all.any((login) => login.isPinned) ? true : keep);
  // A login the kept one doesn't link to a code keeps the link of the copy that goes (the newest first): the link is not lost
  if (kept.accountId == null) {
    for (final login in others) {
      if (login.accountId != null) {
        out = out.copyWith(accountId: login.accountId);
        break;
      }
    }
  }
  // No password is lost: the ones not kept become previous passwords, the newest change first
  final lost = <String>{
    if (kept.password != null) kept.password!,
    for (final login in readable)
      if (login.password != null) login.password!,
  }..remove(out.password);
  var i = 0;
  for (final old in lost) {
    out = out.keepingPrevious(old, now - i++);
  }
  for (final login in [kept, ...readable]) {
    for (final previous in login.previousPasswords ?? const <PreviousPassword>[]) {
      out = out.keepingPrevious(previous.password, previous.until);
    }
  }
  return out;
}

/// How narrow a website rule is, the narrowest first, as design 6 has them: never, exact, starts
/// with, host, base domain, then the default.
int _narrowness(WebsiteRule rule) => switch (rule.match) {
  WebsiteMatch.never => 0,
  WebsiteMatch.exact => 1,
  WebsiteMatch.startsWith => 2,
  WebsiteMatch.host => 3,
  WebsiteMatch.baseDomain => 4,
  null => 5,
  _ => 6,
};

/// The websites of every list in [lists], each address once, in the order they first appear. One
/// address with two rules keeps the narrower. A regular expression, or a rule this version
/// doesn't know, stays as it is and is not joined with another.
List<WebsiteRule> mergeRules(Iterable<List<WebsiteRule>> lists) {
  final out = <WebsiteRule>[];
  final place = <String, int>{};
  for (final rules in lists) {
    for (final rule in rules) {
      final joinable = rule.isKnown && rule.match != WebsiteMatch.regularExpression;
      if (!joinable) {
        if (!out.contains(rule)) {
          out.add(rule);
        }
        continue;
      }
      final at = place[rule.uri];
      if (at == null) {
        place[rule.uri] = out.length;
        out.add(rule);
      } else if (_narrowness(rule) < _narrowness(out[at])) {
        out[at] = rule;
      }
    }
  }
  return out;
}

/// The name a merge record gives each kind of item, and what reads it back.
String mergeKindOf(Object item) => switch (item) {
  OtpAccount() => 'account',
  BackupService() => 'service',
  SecureNote() => 'note',
  Passkey() => 'passkey',
  VaultKey() => 'key',
  Contact() => 'contact',
  Login() => 'login',
  PaymentCard() => 'card',
  Identity() => 'identity',
  _ => throw ArgumentError.value(item, 'item', 'is not an item a merge keeps'),
};

/// [item] as the vault keeps it.
Map<String, Object?> mergeJsonOf(Object item) => switch (item) {
  final OtpAccount item => item.toJson(),
  final BackupService item => item.toJson(),
  final SecureNote item => item.toJson(),
  final Passkey item => item.toJson(),
  final VaultKey item => item.toJson(),
  final Contact item => item.toJson(),
  final Login item => item.toJson(),
  final PaymentCard item => item.toJson(),
  final Identity item => item.toJson(),
  _ => throw ArgumentError.value(item, 'item', 'is not an item a merge keeps'),
};

/// The item of kind [kind] (`mergeKindOf`) that [json] holds; null for a kind this version doesn't know.
Object? mergeItemOf(String kind, Map<String, Object?> json) => switch (kind) {
  'account' => OtpAccount.fromJson(json),
  'service' => BackupService.fromJson(json),
  'note' => SecureNote.fromJson(json),
  'passkey' => Passkey.fromJson(json),
  'key' => VaultKey.fromJson(json),
  'contact' => Contact.fromJson(json),
  'login' => Login.fromJson(json),
  'card' => PaymentCard.fromJson(json),
  'identity' => Identity.fromJson(json),
  _ => null,
};

/// How long Undo merge stays offered.
const mergeUndoDays = 30;

/// What the answers hold of merges and dismissals, read and changed as values.
extension MergeAnswers on DedupAnswers {
  /// The merge records this version reads, oldest first. One a later version wrote that doesn't
  /// read stays in [merges] and is left alone.
  List<MergeRecord> get mergeRecords => [for (final json in merges) ?MergeRecord.fromJson(json)];

  /// These answers with the group [key] dismissed (`DuplicateGroup.key`).
  DedupAnswers withDismissed(String key) =>
      dismissed.contains(key) ? this : DedupAnswers(dismissed: [...dismissed, key], merges: merges, extra: extra);

  /// These answers with [record] added.
  DedupAnswers withMerge(MergeRecord record) => DedupAnswers(dismissed: dismissed, merges: [...merges, record.toJson()], extra: extra);

  /// These answers without the record with [id].
  DedupAnswers withoutMerge(String id) => DedupAnswers(
    dismissed: dismissed,
    merges: [
      for (final json in merges)
        if (MergeRecord.fromJson(json)?.id != id) json,
    ],
    extra: extra,
  );

  /// These answers without the records Undo is no longer offered for at [now] (epoch ms). A record
  /// that doesn't read stays.
  DedupAnswers pruned(int now) => DedupAnswers(
    dismissed: dismissed,
    merges: [
      for (final json in merges)
        if (MergeRecord.fromJson(json)?.undoable(now) ?? true) json,
    ],
    extra: extra,
  );
}

/// What a merge did, kept so Undo can put it back (design 7): the kept item and the removed ones as
/// they were, and the logins that were linked to a code that went, as they were. Written before
/// anything else is changed, so a merge that stopped half way can be repaired.
final class MergeRecord {
  const MergeRecord({
    required this.id,
    required this.at,
    required this.kind,
    required this.kept,
    required this.removed,
    this.relinked = const [],
    this.extra = const {},
  });

  /// Reads a stored record; null for anything else.
  static MergeRecord? fromJson(Object? json) {
    if (json is! Map) {
      return null;
    }
    final id = json['id'];
    final at = json['at'];
    final kind = json['kind'];
    final kept = json['kept'];
    final removed = json['removed'];
    final relinked = json['relinked'];
    if (id is! String || at is! int || kind is! String || kept is! Map || removed is! List) {
      return null;
    }
    Map<String, Object?> object(Object? value) => Map<String, Object?>.from(value! as Map);
    return MergeRecord(
      id: id,
      at: at,
      kind: kind,
      kept: object(kept),
      removed: [
        for (final item in removed)
          if (item is Map) object(item),
      ],
      relinked: relinked is List
          ? [
              for (final item in relinked)
                if (item is Map) object(item),
            ]
          : const [],
      extra: extraKeys(Map<String, Object?>.from(json), const {'id', 'at', 'kind', 'kept', 'removed', 'relinked'}),
    );
  }

  final String id;

  /// Epoch ms the merge was made.
  final int at;

  /// `mergeKindOf` the items.
  final String kind;

  /// The item that stayed, before the merge.
  final Map<String, Object?> kept;

  /// The items that went.
  final List<Map<String, Object?>> removed;

  /// The logins that were relinked to the code that stayed, before the merge.
  final List<Map<String, Object?>> relinked;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// What the kept item was called: its name, issuer, service name or title, or empty.
  String get label {
    for (final key in const ['name', 'issuer', 'serviceName', 'title']) {
      final value = kept[key];
      if (value is String && value.isNotEmpty) {
        return value;
      }
    }
    return '';
  }

  /// Whether Undo is still offered at [now] (epoch ms).
  bool undoable(int now) => now - at < const Duration(days: mergeUndoDays).inMilliseconds;

  Map<String, Object?> toJson() => {'id': id, 'at': at, 'kind': kind, 'kept': kept, 'removed': removed, 'relinked': relinked, ...extra};
}

/// What Undo merge puts back (design 7), worked out from the record and the items the vault holds now, so that nothing the person
/// did since the merge is overwritten without their say:
///
/// - the items that went come back as they were, unless the vault holds one with that id again;
/// - a login the merge relinked to the code that stayed gets only its `accountId` back, and only while it still points at that code:
///   a login edited since, or linked elsewhere, keeps what it holds;
/// - the item that stayed goes back to what it was before the merge, which loses any change made to it since. [keptEdited] says it was
///   changed after the merge (its change time is later than [MergeRecord.at], which the merge stamped it with), and the caller asks first.
class MergeUndo {
  const MergeUndo({required this.kept, required this.keptEdited, required this.keptGone, required this.removed, required this.relinks});

  /// The item that stayed, as it was before the merge.
  final Object kept;

  /// The item that stayed was changed after the merge.
  final bool keptEdited;

  /// The item that stayed is no longer in the vault.
  final bool keptGone;

  /// The items that went, as they were, which the vault doesn't hold now.
  final List<Object> removed;

  /// Login id to the `accountId` it had before the merge, for the logins that still point at the code that stayed.
  final Map<String, String> relinks;
}

/// The plan to undo [record], or null when the record's items can't be read. [find] gives the item the vault holds with an id, or null.
MergeUndo? planUndo(MergeRecord record, {required Object? Function(String id) find}) {
  final kept = mergeItemOf(record.kind, record.kept);
  if (kept is! VaultEntry<Object?>) return null;
  final removed = <Object>[
    for (final json in record.removed)
      if (mergeItemOf(record.kind, json) case final VaultEntry<Object?> item when find(item.id) == null) item,
  ];
  final now = find(kept.id);
  final relinks = <String, String>{};
  for (final json in record.relinked) {
    final before = Login.fromJson(json);
    final held = find(before.id);
    final link = before.accountId;
    if (held is Login && link != null && held.accountId == kept.id) {
      relinks[before.id] = link;
    }
  }
  return MergeUndo(
    kept: kept,
    keptEdited: now is VaultEntry<Object?> && now.changedAt > record.at,
    keptGone: now == null,
    removed: removed,
    relinks: relinks,
  );
}
