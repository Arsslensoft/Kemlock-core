// Credential Exchange Format 1.0 (FIDO Alliance, Proposed Standard of 14
// August 2025, and its errata of 9 March 2026), read into small immutable
// records. Written from the specification alone, never from another
// manager's importer (the add-credential-exchange plan, decision 10).
//
// This is the first of two steps (decision 2): it applies the format's
// version rule, its rules for unknown fields and enumeration values and
// the limits below, and a mapper then turns the records into Kemlock's
// kinds. Pure Dart, no Flutter: it moves into `kemlock_core` with the
// other importers.
//
// Nothing here puts a value into an error: a payload's values stay in the
// records and in memory only while it is read and previewed.
import 'dart:convert';

/// The most characters of a payload that are parsed: 32 MiB, checked on the
/// string's length before `jsonDecode`.
const cxfMaxPayloadChars = 32 * 1024 * 1024;

/// The most items offered across every account; the rest are counted in
/// [CxfCuts.itemsLeftOut].
const cxfMaxItems = 10000;

/// The most credentials read from one item.
const cxfMaxCredentialsPerItem = 32;

/// The most URLs read from one scope.
const cxfMaxUrlsPerScope = 64;

/// How deep collections are read, the top level being 1. Deeper ones give no
/// tags.
const cxfMaxCollectionDepth = 8;

/// The most characters of a field, a title or any other text.
const cxfMaxFieldChars = 4096;

/// The most characters of a note.
const cxfMaxNoteChars = 64 * 1024;

/// A passkey's PKCS#8 key over this many bytes is skipped.
const cxfMaxPasskeyKeyBytes = 2048;

/// An SSH key's PKCS#8 key over this many bytes is skipped.
const cxfMaxSshKeyBytes = 16 * 1024;

// The base64url text of a key up to a size past the two limits above, so a
// key over its limit is skipped by name instead of being dropped here.
const _maxKeyChars = 32 * 1024;

/// Why a payload couldn't be read.
enum CxfProblem {
  /// Over [cxfMaxPayloadChars]; nothing was parsed.
  tooLarge,

  /// Not JSON.
  notJson,

  /// JSON, but not an object.
  notCxf,

  /// An object with no readable `version`.
  noVersion,

  /// A major version other than 1; [CxfException.version] names it.
  unsupportedVersion,

  /// A structure of the wrong shape; [CxfException.position] names where.
  malformed,
}

/// A payload that can't be read. It never holds a value of the payload:
/// [position] says where, such as `account 1, item 7`, and [detail] is fixed
/// English for logs.
class CxfException implements Exception {
  const CxfException(this.problem, {this.version, this.position, this.detail});

  final CxfProblem problem;

  /// For [CxfProblem.unsupportedVersion], `major.minor` as found: `2.0`.
  final String? version;

  /// For [CxfProblem.malformed], where the problem is: `account 1, item 7`.
  final String? position;
  final String? detail;

  String get message => switch (problem) {
    CxfProblem.tooLarge => 'The export is larger than Kemlock reads',
    CxfProblem.notJson => 'The export is not JSON',
    CxfProblem.notCxf => 'The export is not a Credential Exchange payload',
    CxfProblem.noVersion => 'The export has no Credential Exchange version',
    CxfProblem.unsupportedVersion => 'Credential Exchange version $version is not read',
    CxfProblem.malformed => 'Malformed export at $position${detail == null ? '' : ': $detail'}',
  };

  @override
  String toString() => 'CxfException: $message';
}

/// What a read left out because of a limit, so the preview can say so.
class CxfCuts {
  /// Items past [cxfMaxItems].
  int itemsLeftOut = 0;

  /// Credentials past [cxfMaxCredentialsPerItem] in an item.
  int credentialsLeftOut = 0;

  /// URLs past [cxfMaxUrlsPerScope] in a scope.
  int urlsLeftOut = 0;

  /// Collections deeper than [cxfMaxCollectionDepth].
  int collectionsTooDeep = 0;

  /// Texts longer than [cxfMaxFieldChars] (or [cxfMaxNoteChars] for a note),
  /// which were left out.
  int valuesTooLong = 0;

  bool get any => itemsLeftOut + credentialsLeftOut + urlsLeftOut + collectionsTooDeep + valuesTooLong > 0;
}

/// A CXF payload: its header and accounts.
class CxfDocument {
  const CxfDocument({
    required this.major,
    required this.minor,
    required this.exporterRpId,
    required this.exporterDisplayName,
    required this.timestamp,
    required this.accounts,
    required this.cuts,
  });

  final int major;
  final int minor;
  final String exporterRpId;

  /// The exporter's name for people; its relying party id when it gave none.
  final String exporterDisplayName;

  /// Seconds since 1970, 0 when absent.
  final int timestamp;
  final List<CxfAccount> accounts;
  final CxfCuts cuts;

  /// Every credential of every item, for counting.
  Iterable<CxfCredential> get credentials => [
    for (final account in accounts)
      for (final item in account.items) ...item.credentials,
  ];
}

class CxfAccount {
  const CxfAccount({
    required this.id,
    required this.username,
    required this.email,
    this.fullName,
    required this.collections,
    required this.items,
  });

  final String id;
  final String username;
  final String email;
  final String? fullName;

  /// Every collection read, parents before their children, each with its
  /// path.
  final List<CxfCollection> collections;
  final List<CxfItem> items;

  /// What the account is called for people.
  String get displayName {
    for (final name in [fullName, username, email]) {
      if (name != null && name.trim().isNotEmpty) {
        return name.trim();
      }
    }
    return '';
  }
}

/// A collection and where it sits. Collections are read into a flat list
/// without recursion, so a [path] stands for the parents.
class CxfCollection {
  const CxfCollection({required this.id, required this.path, required this.links, this.shared});

  final String id;

  /// The titles from the top level down to this collection.
  final List<String> path;
  final List<CxfLink> links;

  /// Set when the collection carries the `shared` extension.
  final CxfShared? shared;

  /// The tag it gives: the path joined by " / ".
  String get tag => path.join(' / ');
}

/// An item a collection holds, in this account or in another.
class CxfLink {
  const CxfLink({required this.item, this.account});

  final String item;

  /// The account the item belongs to, null for the collection's own.
  final String? account;
}

/// The `shared` extension, with the accessors a reader may use: those of a
/// known type with at least one known permission.
class CxfShared {
  const CxfShared(this.accessors);

  final List<CxfAccessor> accessors;

  /// Whether anyone but the account [ownerId] has access.
  bool sharedBeyond(String ownerId) => accessors.any((accessor) => accessor.accountId != ownerId);
}

class CxfAccessor {
  const CxfAccessor({required this.type, required this.accountId, required this.name, required this.permissions});

  /// `user` or `group`.
  final String type;
  final String accountId;
  final String name;
  final List<String> permissions;
}

class CxfItem {
  const CxfItem({
    required this.id,
    required this.title,
    this.subtitle,
    this.favorite = false,
    this.createdAt,
    this.modifiedAt,
    this.urls = const [],
    this.androidApps = 0,
    required this.credentials,
    this.tags = const [],
    this.shared,
  });

  final String id;
  final String title;
  final String? subtitle;
  final bool favorite;

  /// Seconds since 1970.
  final int? createdAt;
  final int? modifiedAt;

  /// The scope's URLs, at most [cxfMaxUrlsPerScope].
  final List<String> urls;

  /// How many Android apps the scope names; Kemlock keeps none of them.
  final int androidApps;
  final List<CxfCredential> credentials;
  final List<String> tags;
  final CxfShared? shared;
}

/// A value the owner can edit: `EditableField` of the format.
class CxfField {
  const CxfField(this.fieldType, this.value, [this.label]);

  final String fieldType;
  final String value;
  final String? label;

  bool get concealed => fieldType == 'concealed-string';

  @override
  String toString() => 'CxfField($fieldType)';
}

/// What a credential is, as its `type` says.
sealed class CxfCredential {
  const CxfCredential();

  String get type;
}

/// A credential made of editable fields, named by their member.
mixin CxfFielded {
  Map<String, CxfField> get fields;

  /// The trimmed value of [name], null when absent or blank.
  String? valueOf(String name) {
    final value = fields[name]?.value.trim();
    return value == null || value.isEmpty ? null : value;
  }
}

final class CxfBasicAuth extends CxfCredential with CxfFielded {
  const CxfBasicAuth(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'basic-auth';
}

final class CxfCreditCard extends CxfCredential with CxfFielded {
  const CxfCreditCard(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'credit-card';
}

final class CxfAddress extends CxfCredential with CxfFielded {
  const CxfAddress(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'address';
}

final class CxfDriversLicense extends CxfCredential with CxfFielded {
  const CxfDriversLicense(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'drivers-license';
}

final class CxfIdentityDocument extends CxfCredential with CxfFielded {
  const CxfIdentityDocument(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'identity-document';
}

final class CxfPassport extends CxfCredential with CxfFielded {
  const CxfPassport(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'passport';
}

final class CxfPersonName extends CxfCredential with CxfFielded {
  const CxfPersonName(this.fields);

  @override
  final Map<String, CxfField> fields;

  @override
  String get type => 'person-name';
}

final class CxfNote extends CxfCredential {
  const CxfNote(this.content);

  /// The note's text, at most [cxfMaxNoteChars].
  final String content;

  @override
  String get type => 'note';
}

/// `custom-fields`: a labelled group of fields.
final class CxfCustomFields extends CxfCredential {
  const CxfCustomFields({this.label, required this.fields});

  final String? label;

  /// The fields of a known field type, in order.
  final List<CxfField> fields;

  @override
  String get type => 'custom-fields';
}

/// A TOTP credential. [algorithm] is as given, lowercase, for the mapper to
/// judge: the format says to ignore an entry with an unknown one.
final class CxfTotp extends CxfCredential {
  const CxfTotp({required this.secret, required this.period, required this.digits, required this.algorithm, this.username, this.issuer});

  final String secret;
  final int period;
  final int digits;
  final String algorithm;
  final String? username;
  final String? issuer;

  @override
  String get type => 'totp';
}

/// The WebAuthn extensions a passkey came with. Kemlock's authenticator
/// serves none of them, so a reader only needs to know they were there.
class CxfFido2Extensions {
  const CxfFido2Extensions({this.hmacCredentials = false, this.credBlob = false, this.largeBlob = false, this.payments = false});

  /// A `prf` or `hmac-secret` secret of a known algorithm.
  final bool hmacCredentials;
  final bool credBlob;
  final bool largeBlob;
  final bool payments;

  bool get any => hmacCredentials || credBlob || largeBlob || payments;
}

final class CxfPasskey extends CxfCredential {
  const CxfPasskey({
    required this.credentialId,
    required this.rpId,
    required this.username,
    required this.userDisplayName,
    required this.userHandle,
    required this.key,
    this.fido2Extensions,
  });

  /// base64url.
  final String credentialId;
  final String rpId;
  final String username;
  final String userDisplayName;

  /// base64url.
  final String userHandle;

  /// The private key, PKCS#8 DER in base64url.
  final String key;
  final CxfFido2Extensions? fido2Extensions;

  @override
  String get type => 'passkey';

  /// Never the key.
  @override
  String toString() => 'CxfPasskey($rpId)';
}

final class CxfSshKey extends CxfCredential {
  const CxfSshKey({required this.keyType, required this.privateKey, this.keyComment});

  /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`.
  final String keyType;

  /// PKCS#8 DER in base64url.
  final String privateKey;
  final String? keyComment;

  @override
  String get type => 'ssh-key';

  /// Never the key.
  @override
  String toString() => 'CxfSshKey($keyType)';
}

/// A credential of a type the format defines and Kemlock doesn't keep:
/// `file`, `wifi`, `api-key`, `generated-password` and `item-reference`.
/// [name] is a file's name.
final class CxfUnsupported extends CxfCredential {
  const CxfUnsupported(this.type, {this.name});

  @override
  final String type;
  final String? name;
}

/// A credential of a type this version doesn't know.
final class CxfUnknown extends CxfCredential {
  const CxfUnknown(this.type);

  /// The type as given, or '' when it gave none.
  @override
  final String type;
}

/// A credential of a known type that a required member's unknown value, or
/// absence, left out (design: "drop the structure").
final class CxfUnreadable extends CxfCredential {
  const CxfUnreadable(this.type);

  @override
  final String type;
}

typedef _Json = Map<String, Object?>;

const _fieldTypes = {
  'string',
  'concealed-string',
  'email',
  'number',
  'boolean',
  'date',
  'year-month',
  'wifi-network-security-type',
  'country-code',
  'subdivision-code',
};

// The members of each editable-field credential. Others are ignored.
const _members = <String, Set<String>>{
  'basic-auth': {'username', 'password'},
  'credit-card': {'number', 'fullName', 'cardType', 'verificationNumber', 'pin', 'expiryDate', 'validFrom'},
  'address': {'streetAddress', 'postalCode', 'city', 'territory', 'country', 'tel'},
  'drivers-license': {
    'fullName',
    'birthDate',
    'issueDate',
    'expiryDate',
    'issuingAuthority',
    'territory',
    'country',
    'licenseNumber',
    'licenseClass',
  },
  'identity-document': {
    'issuingCountry',
    'documentNumber',
    'identificationNumber',
    'nationality',
    'fullName',
    'birthDate',
    'birthPlace',
    'sex',
    'issueDate',
    'expiryDate',
    'issuingAuthority',
  },
  'passport': {
    'issuingCountry',
    'passportType',
    'passportNumber',
    'nationalIdentificationNumber',
    'nationality',
    'fullName',
    'birthDate',
    'birthPlace',
    'sex',
    'issueDate',
    'expiryDate',
    'issuingAuthority',
  },
  'person-name': {'title', 'given', 'givenInformal', 'given2', 'surnamePrefix', 'surname', 'surname2', 'credentials', 'generation'},
};

const _unsupportedTypes = {'file', 'wifi', 'api-key', 'generated-password', 'item-reference'};
const _accessorTypes = {'user', 'group'};
const _permissions = {'read', 'readSecret', 'update', 'create', 'delete', 'share', 'manage'};

/// Whether [json] is a CXF payload by its keys: a `version` with a `major`,
/// an `exporterRpId` and an `accounts` array. Neither Bitwarden's nor the
/// other importers' formats have all three.
bool looksLikeCxf(Map<String, Object?> json) {
  final version = json['version'];
  return version is _Json && version.containsKey('major') && json['exporterRpId'] is String && json['accounts'] is List<Object?>;
}

/// The exporter's name for people, from a payload's header alone; null when
/// [json] gives neither a display name nor a relying party id.
String? cxfExporterName(Map<String, Object?> json) {
  for (final key in ['exporterDisplayName', 'exporterRpId']) {
    final value = json[key];
    if (value is String && value.trim().isNotEmpty && value.length <= cxfMaxFieldChars) {
      return value.trim();
    }
  }
  return null;
}

/// Reads a CXF payload from its text. Throws a [CxfException]: [CxfProblem.tooLarge]
/// before parsing anything, [CxfProblem.unsupportedVersion] before reading
/// an account, and [CxfProblem.malformed] when a structure has the wrong shape.
CxfDocument parseCxf(String text) {
  if (text.length > cxfMaxPayloadChars) {
    throw const CxfException(CxfProblem.tooLarge);
  }
  final Object? json;
  try {
    json = jsonDecode(text.startsWith('\u{FEFF}') ? text.substring(1) : text);
  } on FormatException {
    // Its message quotes the text, which holds secrets
    throw const CxfException(CxfProblem.notJson);
  }
  return readCxf(json);
}

/// Reads a decoded payload, as [parseCxf] does.
CxfDocument readCxf(Object? json) {
  if (json is! _Json) {
    throw const CxfException(CxfProblem.notCxf);
  }
  final version = json['version'];
  final major = version is _Json ? _int(version['major']) : null;
  if (major == null) {
    throw const CxfException(CxfProblem.noVersion);
  }
  final minor = _int((version! as _Json)['minor']) ?? 0;
  if (major != 1) {
    throw CxfException(CxfProblem.unsupportedVersion, version: '$major.$minor');
  }
  final accounts = json['accounts'];
  if (accounts is! List<Object?>) {
    throw const CxfException(CxfProblem.malformed, position: 'header', detail: 'accounts is not a list');
  }
  final cuts = CxfCuts();
  final reader = _Reader(cuts);
  final rpId = reader.text(json['exporterRpId']) ?? '';
  final read = <CxfAccount>[];
  var items = 0;
  for (var i = 0; i < accounts.length; i++) {
    final account = accounts[i];
    if (account is! _Json) {
      throw CxfException(CxfProblem.malformed, position: 'account ${i + 1}', detail: 'not an object');
    }
    final left = cxfMaxItems - items;
    final parsed = reader.account(account, i + 1, left);
    items += parsed.items.length;
    read.add(parsed);
  }
  return CxfDocument(
    major: major,
    minor: minor,
    exporterRpId: rpId,
    exporterDisplayName: reader.text(json['exporterDisplayName']) ?? rpId,
    timestamp: _int(json['timestamp']) ?? 0,
    accounts: read,
    cuts: cuts,
  );
}

/// A whole number, also from a JSON number written with a fraction, such as `1.0`.
int? _int(Object? v) => switch (v) {
  int() => v,
  double() when v.isFinite && v == v.truncateToDouble() => v.toInt(),
  _ => null,
};

class _Node {
  const _Node(this.json, this.parent, this.depth);

  final _Json json;
  final List<String> parent;
  final int depth;
}

/// The reading of one payload, which counts what the limits cut.
class _Reader {
  _Reader(this.cuts);

  final CxfCuts cuts;

  /// [v] when it is text no longer than [max]; one that is longer is counted and left out.
  String? text(Object? v, {int max = cxfMaxFieldChars}) {
    if (v is! String) {
      return null;
    }
    if (v.length > max) {
      cuts.valuesTooLong++;
      return null;
    }
    return v;
  }

  /// An `EditableField`; null when it is something else or holds a field
  /// type the format doesn't list (the member is then as if absent).
  CxfField? field(Object? v, {int max = cxfMaxFieldChars}) {
    if (v is! _Json) {
      return null;
    }
    final type = v['fieldType'];
    if (type is! String || !_fieldTypes.contains(type)) {
      return null;
    }
    final value = text(v['value'], max: max);
    if (value == null) {
      return null;
    }
    return CxfField(type, value, text(v['label']));
  }

  CxfAccount account(_Json json, int position, int itemsLeft) {
    final id = text(json['id']) ?? '';
    final items = <CxfItem>[];
    final rawItems = json['items'];
    if (rawItems is List<Object?>) {
      for (var j = 0; j < rawItems.length; j++) {
        if (items.length >= itemsLeft) {
          cuts.itemsLeftOut += rawItems.length - j;
          break;
        }
        final item = rawItems[j];
        if (item is! _Json) {
          throw CxfException(CxfProblem.malformed, position: 'account $position, item ${j + 1}', detail: 'not an object');
        }
        items.add(this.item(item, 'account $position, item ${j + 1}'));
      }
    }
    return CxfAccount(
      id: id,
      username: text(json['username']) ?? '',
      email: text(json['email']) ?? '',
      fullName: text(json['fullName']),
      collections: collections(json['collections'], position),
      items: items,
    );
  }

  /// Collections and their sub-collections as one flat list, parents first,
  /// walked with a stack so that nesting 500 deep costs no recursion.
  List<CxfCollection> collections(Object? raw, int accountPosition) {
    final out = <CxfCollection>[];
    if (raw is! List<Object?>) {
      return out;
    }
    final stack = <_Node>[];
    for (var i = raw.length - 1; i >= 0; i--) {
      final collection = raw[i];
      if (collection is! _Json) {
        throw CxfException(CxfProblem.malformed, position: 'account $accountPosition, collection ${i + 1}', detail: 'not an object');
      }
      stack.add(_Node(collection, const [], 1));
    }
    while (stack.isNotEmpty) {
      final node = stack.removeLast();
      if (node.depth > cxfMaxCollectionDepth) {
        cuts.collectionsTooDeep++;
        continue;
      }
      final path = [...node.parent, text(node.json['title']) ?? ''];
      out.add(
        CxfCollection(
          id: text(node.json['id']) ?? '',
          path: path,
          links: links(node.json['items']),
          shared: shared(node.json['extensions']),
        ),
      );
      final subs = node.json['subCollections'];
      if (subs is List<Object?>) {
        for (var i = subs.length - 1; i >= 0; i--) {
          final sub = subs[i];
          if (sub is _Json) {
            stack.add(_Node(sub, path, node.depth + 1));
          }
        }
      }
    }
    return out;
  }

  List<CxfLink> links(Object? raw) => [
    if (raw is List<Object?>)
      for (final link in raw)
        if (link is _Json)
          if (text(link['item']) case final item?) CxfLink(item: item, account: text(link['account'])),
  ];

  CxfShared? shared(Object? extensions) {
    if (extensions is! List<Object?>) {
      return null;
    }
    for (final extension in extensions) {
      if (extension is! _Json || extension['name'] != 'shared') {
        continue;
      }
      final accessors = <CxfAccessor>[];
      final raw = extension['accessors'];
      if (raw is List<Object?>) {
        for (final entry in raw) {
          if (entry is! _Json) {
            continue;
          }
          final type = entry['type'];
          final accountId = text(entry['accountId']);
          // An accessor of an unknown type, or with no known permission, is ignored
          if (type is! String || !_accessorTypes.contains(type) || accountId == null) {
            continue;
          }
          final permissions = [
            if (entry['permissions'] is List<Object?>)
              for (final permission in entry['permissions']! as List<Object?>)
                if (permission is String && _permissions.contains(permission)) permission,
          ];
          if (permissions.isNotEmpty) {
            accessors.add(CxfAccessor(type: type, accountId: accountId, name: text(entry['name']) ?? '', permissions: permissions));
          }
        }
      }
      return CxfShared(accessors);
    }
    return null;
  }

  CxfItem item(_Json json, String position) {
    final scope = json['scope'];
    final urls = <String>[];
    var androidApps = 0;
    if (scope is _Json) {
      final rawUrls = scope['urls'];
      if (rawUrls is List<Object?>) {
        for (final url in rawUrls) {
          if (url is! String) {
            continue;
          }
          if (urls.length >= cxfMaxUrlsPerScope) {
            cuts.urlsLeftOut++;
          } else if (url.length > cxfMaxFieldChars) {
            cuts.valuesTooLong++;
          } else {
            urls.add(url);
          }
        }
      }
      final apps = scope['androidApps'];
      androidApps = apps is List<Object?> ? apps.length : 0;
    }
    final credentials = <CxfCredential>[];
    final rawCredentials = json['credentials'];
    if (rawCredentials is List<Object?>) {
      for (var k = 0; k < rawCredentials.length; k++) {
        if (k >= cxfMaxCredentialsPerItem) {
          cuts.credentialsLeftOut += rawCredentials.length - k;
          break;
        }
        final credential = rawCredentials[k];
        if (credential is! _Json) {
          throw CxfException(CxfProblem.malformed, position: '$position, credential ${k + 1}', detail: 'not an object');
        }
        credentials.add(this.credential(credential));
      }
    }
    return CxfItem(
      id: text(json['id']) ?? '',
      title: text(json['title']) ?? '',
      subtitle: text(json['subtitle']),
      favorite: json['favorite'] == true,
      createdAt: _int(json['creationAt']),
      modifiedAt: _int(json['modifiedAt']),
      urls: urls,
      androidApps: androidApps,
      credentials: credentials,
      tags: [
        if (json['tags'] is List<Object?>)
          for (final entry in json['tags']! as List<Object?>) ?text(entry),
      ],
      shared: shared(json['extensions']),
    );
  }

  CxfCredential credential(_Json json) {
    final type = json['type'];
    if (type is! String) {
      return const CxfUnknown('');
    }
    final members = _members[type];
    if (members != null) {
      final fields = <String, CxfField>{for (final name in members) name: ?field(json[name])};
      return switch (type) {
        'basic-auth' => CxfBasicAuth(fields),
        'credit-card' => CxfCreditCard(fields),
        'address' => CxfAddress(fields),
        'drivers-license' => CxfDriversLicense(fields),
        'identity-document' => CxfIdentityDocument(fields),
        'passport' => CxfPassport(fields),
        _ => CxfPersonName(fields),
      };
    }
    if (_unsupportedTypes.contains(type)) {
      return CxfUnsupported(type, name: type == 'file' ? text(json['name']) : null);
    }
    return switch (type) {
      'note' => switch (field(json['content'], max: cxfMaxNoteChars)) {
        // A note's content is required: without it the credential is dropped
        final content? => CxfNote(content.value),
        null => const CxfUnreadable('note'),
      },
      'custom-fields' => customFields(json),
      'totp' => totp(json),
      'passkey' => passkey(json),
      'ssh-key' => sshKey(json),
      _ => CxfUnknown(type),
    };
  }

  CxfCredential customFields(_Json json) {
    final raw = json['fields'];
    return CxfCustomFields(
      label: text(json['label']),
      fields: [
        if (raw is List<Object?>)
          for (final entry in raw) ?field(entry),
      ],
    );
  }

  CxfCredential totp(_Json json) {
    final secret = text(json['secret']);
    if (secret == null) {
      return const CxfUnreadable('totp');
    }
    final algorithm = text(json['algorithm']);
    return CxfTotp(
      secret: secret,
      period: _int(json['period']) ?? 30,
      digits: _int(json['digits']) ?? 6,
      algorithm: (algorithm ?? 'sha1').toLowerCase(),
      username: text(json['username']),
      issuer: text(json['issuer']),
    );
  }

  CxfCredential passkey(_Json json) {
    final credentialId = text(json['credentialId']);
    final rpId = text(json['rpId']);
    final userHandle = text(json['userHandle']);
    final key = text(json['key'], max: _maxKeyChars);
    if (credentialId == null || rpId == null || userHandle == null || key == null) {
      return const CxfUnreadable('passkey');
    }
    return CxfPasskey(
      credentialId: credentialId,
      rpId: rpId,
      username: text(json['username']) ?? '',
      userDisplayName: text(json['userDisplayName']) ?? '',
      userHandle: userHandle,
      key: key,
      fido2Extensions: fido2(json['fido2Extensions']),
    );
  }

  CxfFido2Extensions? fido2(Object? raw) {
    if (raw is! _Json) {
      return null;
    }
    final hmac = raw['hmacCredentials'];
    return CxfFido2Extensions(
      // An entry of an unknown algorithm is ignored
      hmacCredentials: hmac is _Json && hmac['algorithm'] == 'hmac-sha256',
      credBlob: raw['credBlob'] is String,
      largeBlob: raw['largeBlob'] is _Json,
      payments: raw['payments'] == true,
    );
  }

  CxfCredential sshKey(_Json json) {
    final keyType = text(json['keyType']);
    final privateKey = text(json['privateKey'], max: _maxKeyChars);
    if (keyType == null || privateKey == null) {
      return const CxfUnreadable('ssh-key');
    }
    return CxfSshKey(keyType: keyType, privateKey: privateKey, keyComment: text(json['keyComment']));
  }
}
