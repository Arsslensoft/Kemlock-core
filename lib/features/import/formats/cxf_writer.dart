// What Kemlock's items become as a Credential Exchange payload (the
// add-credential-exchange plan, design decision 11): the mapping of
// `cxf_map.dart` in reverse, written from the CXF 1.0 specification and its
// errata only.
//
// - a login is an item with a `basic-auth` credential and its websites as
//   scope URLs; its linked code is a `totp` in the same item; its note is a
//   `note`;
// - a code that no login links to is an item of its own, as a passkey (ES256),
//   a note, a card, an identity (`person-name`, `address` and one document
//   credential each) and an SSH key are;
// - tags become collections, a tag written "Parent / Child" a collection inside
//   another, and every item is linked from the collection of each of its tags;
// - what CXF has no type for, or can't carry, is left out and listed, each
//   with its reason, never silently.
//
// Pure Dart with no Flutter, like the reader, and nothing here writes to disk
// or logs: the JSON is a string in memory, and the caller hands it to the
// system and drops it.
import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/bytes.dart';
import '../../../models/identity.dart';
import '../../../models/login.dart';
import '../../../models/otp_account.dart';
import '../../../models/passkey.dart';
import '../../../models/payment_card.dart';
import '../../../models/secure_note.dart';
import '../../../models/vault_key.dart';
import '../../../models/website_rule.dart';

/// The relying party id Kemlock names itself with in an export's header.
const cxfExporterRpId = 'kemlock.app';

/// The id of the account an export holds when the caller names none. An export of a vault names the vault's own (see
/// [writeCxf]'s `accountId`), so that the exports of two vaults are not the same account to the app that imports both.
const cxfDefaultAccountId = 'kemlock';

/// The most bytes CXF 1.0 lets an `id` hold, counted before base64url (sections 3.2.1 to 3.2.3).
const _maxIdBytes = 64;

/// `id` as CXF 1.0 writes it: base64url, without padding, of opaque bytes of at most 64. Kemlock's ids are
/// text (a UUID, or a legacy "acc-1"), so the bytes are the id's UTF-8; an id of more than 64 bytes is
/// replaced by its SHA-256, 32 bytes, which is the same each time it is written, as CXF asks. Only the
/// writer does this: the reader takes an id as the opaque string it is.
String cxfId(String id) {
  final bytes = utf8.encode(id);
  return b64url(bytes.length > _maxIdBytes ? hash.sha256.convert(bytes).bytes : bytes);
}

/// Why a thing in the vault isn't in the export.
enum CxfLeftOutReason {
  /// A key that is not an SSH key (a signing, exchange or PGP key): CXF carries no such type.
  notSshKey,

  /// An SSH key held under a passphrase: it can't be written without opening it.
  protectedKey,

  /// A one-time code CXF can't carry: only time-based codes (`totp`) have a type.
  notTotp,

  /// A key or a card Kemlock holds only on a hardware card: there is no private key to write.
  onCard,

  /// A key or a passkey whose algorithm CXF can't name.
  algorithm,
}

/// One thing the export leaves out, by its name and why.
class CxfLeftOut {
  const CxfLeftOut(this.title, this.reason);

  final String title;
  final CxfLeftOutReason reason;
}

/// The items to write. Each list is what the person picked; a kind they didn't pick is empty.
class CxfExportItems {
  const CxfExportItems({
    this.logins = const [],
    this.codes = const [],
    this.passkeys = const [],
    this.notes = const [],
    this.cards = const [],
    this.identities = const [],
    this.keys = const [],
  });

  final List<Login> logins;
  final List<OtpAccount> codes;
  final List<Passkey> passkeys;
  final List<SecureNote> notes;
  final List<PaymentCard> cards;
  final List<Identity> identities;
  final List<VaultKey> keys;
}

/// What [writeCxf] made: the payload, how many items it holds, and what it left out.
class CxfWritten {
  const CxfWritten({required this.json, required this.items, required this.leftOut});

  /// The CXF 1.0 JSON. Every secret of the picked items is in it.
  final String json;

  /// The items in the account.
  final int items;
  final List<CxfLeftOut> leftOut;

  /// Never the payload.
  @override
  String toString() => 'CxfWritten($items items, ${leftOut.length} left out)';
}

/// Writes [items] as one CXF 1.0 account named [exporterDisplayName], made at [now] (epoch ms).
/// A login's linked code goes into the login's item; a code whose login isn't in [items] stands
/// alone. Items come out in the order of the lists, logins first.
///
/// [asked] is the credential types the importing app asked for, when it asked: a credential of any other type is
/// left out of its item, whatever the item, so a login's note or linked code, a passkey's note, an identity's
/// address and the rest go only to an app that asked for their type. An item left with no credential at all is not
/// written. Null writes everything.
///
/// [accountId] is the id of the one account the payload holds: an export of a vault passes the vault's own id, which is
/// what tells the accounts of two vaults apart when one app imports both; it is written as CXF writes every id, by
/// [cxfId].
CxfWritten writeCxf(
  CxfExportItems items, {
  required int now,
  String exporterDisplayName = 'Kemlock',
  String accountId = cxfDefaultAccountId,
  Set<String>? asked,
}) => _Writer(items, now, exporterDisplayName, accountId, asked).write();

const _sshKeyTypes = {'ed25519': 'ssh-ed25519', 'ecdsa-p256': 'ecdsa-sha2-nistp256', 'ecdsa-p384': 'ecdsa-sha2-nistp384', 'rsa': 'ssh-rsa'};

/// Why [code] can't be written, or null when it can: only time-based codes have a type.
CxfLeftOutReason? cxfCodeLeftOut(OtpAccount code) => code.kind == OtpType.totp ? null : CxfLeftOutReason.notTotp;

/// Why [passkey] can't be written, or null when it can. CXF's `passkey` credential carries a PKCS#8 key and names no
/// algorithm, so the importer reads it as the P-256 key for ES256 that Kemlock makes. A passkey of another COSE
/// algorithm would be read as that and never sign, so it is left out and listed.
CxfLeftOutReason? cxfPasskeyLeftOut(Passkey passkey) => passkey.algorithm == coseEs256 ? null : CxfLeftOutReason.algorithm;

/// Why [key] can't be written, or null when it can: an SSH key held in the clear, on this phone, of an
/// algorithm CXF names.
CxfLeftOutReason? cxfKeyLeftOut(VaultKey key) {
  if (key.kind != KeyKind.ssh) {
    return CxfLeftOutReason.notSshKey;
  }
  if (key.protected ?? false) {
    return CxfLeftOutReason.protectedKey;
  }
  if (key.card != null) {
    return CxfLeftOutReason.onCard;
  }
  if (_sshKeyTypes[key.algorithm] == null) {
    return CxfLeftOutReason.algorithm;
  }
  return null;
}

/// What [writeCxf] leaves out of [items], found without writing anything: it looks at no secret, only at
/// each item's kind and settings, so the export sheet can list it before the person has shown it is them.
List<CxfLeftOut> cxfLeftOut(CxfExportItems items) => [
  for (final code in items.codes)
    if (cxfCodeLeftOut(code) case final reason?) CxfLeftOut(code.issuer.isNotEmpty ? code.issuer : code.label, reason),
  for (final passkey in items.passkeys)
    if (cxfPasskeyLeftOut(passkey) case final reason?) CxfLeftOut(passkey.displayName, reason),
  for (final key in items.keys)
    if (cxfKeyLeftOut(key) case final reason?) CxfLeftOut(key.name, reason),
];

class _Writer {
  _Writer(this.source, this.now, this.exporterDisplayName, this.accountId, this.asked);

  final CxfExportItems source;
  final int now;
  final String exporterDisplayName;

  /// The id of the one account, which an export of a vault takes from the vault so that each vault's is its own.
  final String accountId;

  /// The credential types the importer asked for; null for any.
  final Set<String>? asked;

  final _items = <Map<String, Object?>>[];
  final _leftOut = <CxfLeftOut>[];

  /// The tags of each item, by its id, in the order the items were written.
  final _tagsOf = <String, List<String>>{};

  CxfWritten write() {
    final linked = <String>{};
    final codesById = {for (final code in source.codes) code.id: code};
    for (final login in source.logins) {
      final code = login.accountId == null ? null : codesById[login.accountId];
      if (code != null && code.kind == OtpType.totp) {
        linked.add(code.id);
      }
      _login(login, code != null && code.kind == OtpType.totp ? code : null);
    }
    for (final code in source.codes) {
      if (linked.contains(code.id)) {
        continue;
      }
      _code(code);
    }
    source.passkeys.forEach(_passkey);
    source.notes.forEach(_note);
    source.cards.forEach(_card);
    source.identities.forEach(_identity);
    source.keys.forEach(_key);

    final document = <String, Object?>{
      'version': {'major': 1, 'minor': 0},
      'exporterRpId': cxfExporterRpId,
      'exporterDisplayName': exporterDisplayName,
      'timestamp': now ~/ 1000,
      'accounts': [
        {'id': cxfId(accountId), 'username': '', 'email': '', 'collections': _collections(), 'items': _items},
      ],
    };
    return CxfWritten(json: jsonEncode(document), items: _items.length, leftOut: _leftOut);
  }

  // -- items --------------------------------------------------------------------------------------------------

  /// Adds an item. [tags] become the collections that link it, never an `tags` member, so that
  /// reading the payload back gives each tag once.
  void _add(
    String id,
    String title,
    List<Map<String, Object?>> credentials, {
    int? addedAt,
    int? changedAt,
    List<String>? tags,
    bool? pinned,
    List<String>? urls,
    String? subtitle,
  }) {
    // Only what the importer asked for goes, whatever it is attached to
    final wanted = [
      for (final credential in credentials)
        if (asked == null || asked!.contains(credential['type'])) credential,
    ];
    if (wanted.isEmpty) {
      return;
    }
    _items.add({
      'id': cxfId(id),
      'creationAt': ?_seconds(addedAt),
      'modifiedAt': ?_seconds(changedAt ?? addedAt),
      'title': title,
      'subtitle': ?subtitle,
      if (pinned ?? false) 'favorite': true,
      if (urls != null && urls.isNotEmpty) 'scope': {'urls': urls, 'androidApps': <String>[]},
      'credentials': wanted,
    });
    if (tags != null && tags.isNotEmpty) {
      _tagsOf[id] = tags;
    }
  }

  int? _seconds(int? ms) => ms == null || ms <= 0 ? null : ms ~/ 1000;

  void _login(Login login, OtpAccount? code) {
    final urls = <String>[
      for (final rule in login.uris ?? const <WebsiteRule>[]) rule.uri,
      if (login.uris == null)
        for (final host in login.websites ?? const <String>[]) 'https://$host',
    ];
    _add(
      login.id,
      login.name,
      [
        if (login.username != null || login.password != null)
          {'type': 'basic-auth', 'username': ?_field(login.username, 'string'), 'password': ?_field(login.password, 'concealed-string')},
        if (code != null) _totp(code),
        ..._noteCredential(login.note),
      ],
      addedAt: login.addedAt,
      changedAt: login.passwordChangedAt ?? login.updatedAt,
      tags: login.tags,
      pinned: login.pinned,
      urls: urls,
    );
  }

  void _code(OtpAccount code) {
    if (cxfCodeLeftOut(code) case final reason?) {
      _leftOut.add(CxfLeftOut(_codeTitle(code), reason));
      return;
    }
    _add(
      code.id,
      _codeTitle(code),
      [_totp(code), ..._noteCredential(code.note)],
      addedAt: code.addedAt,
      changedAt: code.updatedAt,
      tags: code.tags,
      pinned: code.pinned,
    );
  }

  String _codeTitle(OtpAccount code) => code.issuer.isNotEmpty ? code.issuer : code.label;

  Map<String, Object?> _totp(OtpAccount code) => {
    'type': 'totp',
    'secret': code.secret,
    'period': code.period,
    'digits': code.digits,
    'algorithm': code.algorithm.toLowerCase(),
    if (code.issuer.isNotEmpty) 'issuer': code.issuer,
    if (code.label.isNotEmpty) 'username': code.label,
  };

  void _passkey(Passkey passkey) {
    if (cxfPasskeyLeftOut(passkey) case final reason?) {
      _leftOut.add(CxfLeftOut(passkey.displayName, reason));
      return;
    }
    _add(
      passkey.id,
      passkey.label ?? passkey.rpName ?? passkey.rpId,
      [
        {
          'type': 'passkey',
          'credentialId': passkey.credentialId,
          'rpId': passkey.rpId,
          'username': passkey.userName,
          'userDisplayName': passkey.userDisplayName ?? '',
          'userHandle': passkey.userHandle,
          // Kemlock keeps the key in base64; CXF carries byte strings as base64url
          'key': b64url(unb64(passkey.privateKey)),
        },
        ..._noteCredential(passkey.note),
      ],
      addedAt: passkey.addedAt,
      changedAt: passkey.updatedAt,
      tags: passkey.tags,
      urls: ['https://${passkey.rpId}'],
    );
  }

  void _note(SecureNote note) {
    _add(
      note.id,
      note.title,
      _noteCredential(note.text.isEmpty ? ' ' : note.text),
      addedAt: note.addedAt,
      changedAt: note.updatedAt,
      tags: note.tags,
      pinned: note.pinned,
    );
  }

  void _card(PaymentCard card) {
    _add(
      card.id,
      card.name,
      [
        {
          'type': 'credit-card',
          'number': ?_field(card.number, 'string'),
          'fullName': ?_field(card.cardholder, 'string'),
          'cardType': ?_field(card.brand, 'string'),
          'verificationNumber': ?_field(card.code, 'concealed-string'),
          'pin': ?_field(card.pin, 'concealed-string'),
          'expiryDate': ?_field(_yearMonth(card.expYear, card.expMonth), 'year-month'),
          'validFrom': ?_field(_yearMonth(card.validFromYear, card.validFromMonth), 'year-month'),
        },
        ..._noteCredential(card.note),
      ],
      addedAt: card.addedAt,
      changedAt: card.updatedAt,
      tags: card.tags,
      pinned: card.pinned,
    );
  }

  /// `YYYY-MM`; null without both parts.
  String? _yearMonth(int? year, int? month) =>
      year == null || month == null ? null : '${year.toString().padLeft(4, '0')}-${month.toString().padLeft(2, '0')}';

  void _identity(Identity identity) {
    final address = identity.address;
    final documents = identity.documents ?? const <IdentityDocument>[];
    final other = <Map<String, Object?>>[
      for (final (label, value) in [('Email', identity.email), ('Company', identity.company), ('Username', identity.username)])
        if (value != null && value.isNotEmpty) {'fieldType': value == identity.email ? 'email' : 'string', 'value': value, 'label': label},
    ];
    _add(
      identity.id,
      identity.name,
      [
        if (_any([identity.title, identity.givenName, identity.middleName, identity.familyName]))
          {
            'type': 'person-name',
            'title': ?_field(identity.title, 'string'),
            'given': ?_field(identity.givenName, 'string'),
            'given2': ?_field(identity.middleName, 'string'),
            'surname': ?_field(identity.familyName, 'string'),
          },
        if ((address != null && !address.isEmpty) || (identity.phone?.isNotEmpty ?? false))
          {
            'type': 'address',
            'streetAddress': ?_field(address?.lines?.join('\n'), 'string'),
            'postalCode': ?_field(address?.postalCode, 'string'),
            'city': ?_field(address?.city, 'string'),
            'territory': ?_field(address?.region, 'string'),
            'country': ?_field(address?.country, 'country-code'),
            'tel': ?_field(identity.phone, 'string'),
          },
        for (final (i, document) in documents.indexed) _document(document, i == 0 ? identity.birthDate : null),
        if (documents.isEmpty && (identity.birthDate?.isNotEmpty ?? false))
          {
            'type': 'custom-fields',
            'fields': [
              {'fieldType': 'date', 'value': identity.birthDate, 'label': 'Birth date'},
            ],
          },
        if (other.isNotEmpty) {'type': 'custom-fields', 'fields': other},
        ..._noteCredential(identity.note),
      ],
      addedAt: identity.addedAt,
      changedAt: identity.updatedAt,
      tags: identity.tags,
      pinned: identity.pinned,
    );
  }

  bool _any(List<String?> values) => values.any((value) => value != null && value.isNotEmpty);

  Map<String, Object?> _document(IdentityDocument document, String? birthDate) {
    final type = IdentityDocumentType.fromWire(document.type);
    final dates = {
      'issueDate': ?_field(document.issuedOn, 'date'),
      'expiryDate': ?_field(document.expiresOn, 'date'),
      'issuingAuthority': ?_field(document.issuingAuthority, 'string'),
      'birthDate': ?_field(birthDate, 'date'),
    };
    return switch (type) {
      IdentityDocumentType.passport => {
        'type': 'passport',
        'passportNumber': ?_field(document.number, 'string'),
        'issuingCountry': ?_field(document.issuingCountry, 'country-code'),
        ...dates,
      },
      IdentityDocumentType.driversLicence => {
        'type': 'drivers-license',
        'licenseNumber': ?_field(document.number, 'string'),
        'country': ?_field(document.issuingCountry, 'country-code'),
        ...dates,
      },
      _ => {
        'type': 'identity-document',
        'documentNumber': ?_field(document.number, 'string'),
        'issuingCountry': ?_field(document.issuingCountry, 'country-code'),
        ...dates,
      },
    };
  }

  void _key(VaultKey key) {
    if (cxfKeyLeftOut(key) case final reason?) {
      _leftOut.add(CxfLeftOut(key.name, reason));
      return;
    }
    final keyType = _sshKeyTypes[key.algorithm]!;
    _add(
      key.id,
      key.name,
      [
        {'type': 'ssh-key', 'keyType': keyType, 'privateKey': b64url(unb64(key.privateKey))},
        ..._noteCredential(key.note),
      ],
      addedAt: key.addedAt,
      changedAt: key.updatedAt,
      tags: key.tags,
      pinned: key.pinned,
    );
  }

  // -- parts --------------------------------------------------------------------------------------------------

  /// An `EditableField`; null for a missing or empty value, which the member is then left out for.
  Map<String, Object?>? _field(String? value, String type) => value == null || value.isEmpty ? null : {'fieldType': type, 'value': value};

  List<Map<String, Object?>> _noteCredential(String? text) => text == null || text.trim().isEmpty
      ? const []
      : [
          {
            'type': 'note',
            'content': {'fieldType': 'string', 'value': text},
          },
        ];

  /// The collections of the tags: one tree, "Parent / Child" a child collection of "Parent".
  List<Map<String, Object?>> _collections() {
    final roots = <String, _Node>{};
    for (final entry in _tagsOf.entries) {
      for (final tag in entry.value.toSet()) {
        final path = [for (final part in tag.split(' / ')) part.trim()].where((part) => part.isNotEmpty).toList();
        if (path.isEmpty) {
          continue;
        }
        var level = roots;
        _Node? node;
        for (final part in path) {
          node = level.putIfAbsent(part, () => _Node(part));
          level = node.children;
        }
        node!.itemIds.add(entry.key);
      }
    }
    var next = 0;
    Map<String, Object?> write(_Node node) => {
      'id': cxfId('collection-${next++}'),
      'title': node.title,
      'items': [
        for (final id in node.itemIds) {'item': cxfId(id)},
      ],
      'subCollections': [for (final child in node.children.values) write(child)],
    };
    return [for (final root in roots.values) write(root)];
  }
}

class _Node {
  _Node(this.title);

  final String title;
  final children = <String, _Node>{};
  final itemIds = <String>[];
}
