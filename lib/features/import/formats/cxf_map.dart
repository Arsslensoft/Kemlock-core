// What each Credential Exchange credential becomes in Kemlock (the
// add-credential-exchange plan, design decision 4). The second step of
// `cxf.dart`: records in, a [ForeignImport] of Kemlock's own kinds out.
//
// - `basic-auth` and the item's scope make a login with every URL on the
//   default rule; `totp` a code, linked to the item's first login.
// - an ES256 `passkey` a passkey, an `ssh-key` an SSH key, `credit-card` a
//   card, and `person-name`, `address`, `identity-document`, `passport` and
//   `drivers-license` one identity.
// - `note` and `custom-fields` go into the note of what the item became, or
//   make a note when it became nothing else.
// - `file`, `wifi`, `api-key`, `generated-password`, `item-reference` and
//   unknown types are listed as skipped, each with its reason.
// - collections become tags (nested ones as `Parent / Child`), and each
//   account, and each collection shared with other people, is a place the
//   preview asks about.
//
// Pure Dart, and no value of the payload goes into a skip or a notice.
import '../../../models/identity.dart';
import '../../../models/login.dart';
import '../../../models/otp_account.dart';
import '../../../models/passkey.dart';
import '../../../models/payment_card.dart';
import '../../../models/secure_note.dart';
import '../../../models/vault_key.dart';
import '../../../models/website_rule.dart';
import '../../accounts/otp.dart';
import '../importers.dart';
import 'cxf.dart';
import 'cxf_passkey.dart';
import 'cxf_ssh_key.dart';
import 'import_extras.dart';

/// The most tags an imported item gets.
const _maxTags = 32;

final _base32 = RegExp(r'^[A-Z2-7]+$');
final _trailingPadding = RegExp(r'=+$');
final _yearMonth = RegExp(r'^(\d{4})-(\d{2})$');
final _fullDate = RegExp(r'^\d{4}-\d{2}-\d{2}$');

/// Turns [document] into Kemlock's kinds. [newId] makes the id of each entry
/// (a UUID in the app) and [now] is the import time in epoch ms, used where
/// the payload gives none. Nothing is dropped silently: every credential
/// that isn't kept is in the result's `skips`.
Future<ForeignImport> mapCxf(CxfDocument document, {required String Function() newId, required int now}) =>
    _Mapper(document, newId, now).run();

class _Mapper {
  _Mapper(this.document, this.newId, this.now);

  final CxfDocument document;
  final String Function() newId;
  final int now;

  final accounts = <OtpAccount>[];
  final passkeys = <Passkey>[];
  final logins = <Login>[];
  final cards = <PaymentCard>[];
  final identities = <Identity>[];
  final keys = <VaultKey>[];
  final notes = <SecureNote>[];
  final skips = <ImportSkip>[];
  final notices = <ImportNotice>[];
  final units = <ImportUnit>[];
  final unitOf = <String, String>{};

  Future<ForeignImport> run() async {
    final accountIndex = <String, int>{
      for (var i = 0; i < document.accounts.length; i++)
        if (document.accounts[i].id.isNotEmpty) document.accounts[i].id: i,
    };
    final accountUnits = <int, String>{};
    final collectionUnit = Map<CxfCollection, String>.identity();
    // The collections each item is in, in the order the account lists them
    final collectionsOf = <String, List<CxfCollection>>{};

    for (var i = 0; i < document.accounts.length; i++) {
      final account = document.accounts[i];
      final unit = ImportUnit(id: 'account:$i', name: account.displayName.isEmpty ? document.exporterDisplayName : account.displayName);
      accountUnits[i] = unit.id;
      units.add(unit);
      for (var c = 0; c < account.collections.length; c++) {
        final collection = account.collections[c];
        // A collection shared with anyone but its owner gets a place of its own
        if (collection.shared?.sharedBeyond(account.id) ?? false) {
          final shared = ImportUnit(id: 'account:$i/collection:$c', name: collection.path.last, shared: true);
          collectionUnit[collection] = shared.id;
          units.add(shared);
        }
        for (final link in collection.links) {
          final owner = link.account == null ? i : accountIndex[link.account];
          if (owner != null) {
            (collectionsOf['$owner\u0000${link.item}'] ??= []).add(collection);
          }
        }
      }
    }

    for (var i = 0; i < document.accounts.length; i++) {
      for (final item in document.accounts[i].items) {
        final collections = collectionsOf['$i\u0000${item.id}'] ?? const <CxfCollection>[];
        final unit = (collections.isEmpty ? null : collectionUnit[collections.first]) ?? accountUnits[i]!;
        await _item(item, collections, unit);
      }
    }

    return ForeignImport(
      source: ImportSource.cxf,
      accounts: accounts,
      skipped: skips.length,
      passkeys: passkeys,
      logins: logins,
      cards: cards,
      identities: identities,
      keys: keys,
      notes: notes,
      skips: skips,
      notices: notices,
      units: units,
      unitOf: unitOf,
      cuts: document.cuts,
      sourceName: document.exporterDisplayName,
    );
  }

  /// [id], placed in [unit].
  String _placed(String unit) {
    final id = newId();
    unitOf[id] = unit;
    return id;
  }

  int _ms(int? seconds) => seconds == null || seconds < 0 ? now : seconds * 1000;

  Future<void> _item(CxfItem item, List<CxfCollection> collections, String unit) async {
    final auths = <CxfBasicAuth>[];
    final totps = <CxfTotp>[];
    final passkeySources = <CxfPasskey>[];
    final noteTexts = <String>[];
    final cardSources = <CxfCreditCard>[];
    final sshSources = <CxfSshKey>[];
    final customLines = <String>[];
    final names = <CxfPersonName>[];
    final addresses = <CxfAddress>[];
    final documents = <CxfFielded>[];
    final title = item.title.trim();
    final skipTitle = title.isEmpty ? '' : title;

    if (item.credentials.isEmpty) {
      skips.add(ImportSkip(skipTitle, SkipReason.nothingKept));
      return;
    }
    for (final credential in item.credentials) {
      switch (credential) {
        case CxfBasicAuth():
          auths.add(credential);
        case CxfTotp():
          totps.add(credential);
        case CxfPasskey():
          passkeySources.add(credential);
        case CxfNote(:final content):
          if (content.trim().isNotEmpty) {
            noteTexts.add(content);
          }
        case CxfCreditCard():
          cardSources.add(credential);
        case CxfSshKey(:final keyComment):
          sshSources.add(credential);
          if (keyComment != null && keyComment.trim().isNotEmpty && keyComment.trim() != title) {
            noteTexts.add(keyComment.trim());
          }
        case CxfCustomFields(:final fields):
          customLines.addAll([
            for (final field in fields)
              if (field.value.trim().isNotEmpty) _line(field.label, field),
          ]);
        case CxfPersonName():
          names.add(credential);
        case CxfAddress():
          addresses.add(credential);
        case CxfIdentityDocument() || CxfPassport() || CxfDriversLicense():
          documents.add(credential as CxfFielded);
        case CxfUnsupported(:final type, :final name):
          skips.add(
            ImportSkip(skipTitle, switch (type) {
              'file' => SkipReason.file,
              'wifi' => SkipReason.wifi,
              'api-key' => SkipReason.apiKey,
              'generated-password' => SkipReason.generatedPassword,
              _ => SkipReason.itemReference,
            }, detail: name),
          );
        case CxfUnknown(:final type):
          skips.add(ImportSkip(skipTitle, SkipReason.unknownType, detail: type.isEmpty ? null : type));
        case CxfUnreadable(:final type):
          skips.add(ImportSkip(skipTitle, SkipReason.unreadable, detail: type));
      }
    }

    final tags = _tagList([for (final collection in collections) collection.tag, ...item.tags]);
    final addedAt = _ms(item.createdAt);
    final changedAt = _ms(item.modifiedAt);
    final pinned = item.favorite ? true : null;
    final urls = <String>{
      for (final url in item.urls)
        if (url.trim().isNotEmpty) url.trim(),
    }.toList();
    final rules = [for (final url in urls) WebsiteRule(url)];
    final name = title.isNotEmpty ? title : (urls.isNotEmpty ? urls.first : (auths.isEmpty ? '' : auths.first.valueOf('username') ?? ''));

    // The codes first, so the first login can be linked to the first of them
    final codes = <OtpAccount>[];
    for (final totp in totps) {
      final reason = _totpProblem(totp);
      if (reason != null) {
        skips.add(ImportSkip(skipTitle, reason));
        continue;
      }
      final issuer = totp.issuer?.trim() ?? '';
      codes.add(
        OtpAccount(
          id: _placed(unit),
          type: OtpType.totp,
          issuer: issuer.isEmpty ? name : issuer,
          label: totp.username?.trim().isNotEmpty ?? false
              ? totp.username!.trim()
              : (auths.isEmpty ? '' : auths.first.valueOf('username') ?? ''),
          secret: normalizeSecret(totp.secret).replaceFirst(_trailingPadding, ''),
          algorithm: totp.algorithm.toUpperCase(),
          digits: totp.digits,
          period: totp.period,
          pinned: pinned,
          tags: tags,
          addedAt: addedAt,
        ),
      );
    }
    accounts.addAll(codes);

    final madeLogins = <Login>[];
    for (final auth in auths) {
      final password = auth.fields['password']?.value;
      final username = auth.valueOf('username');
      if (username == null && (password == null || password.isEmpty)) {
        skips.add(ImportSkip(skipTitle, SkipReason.unreadable, detail: 'basic-auth'));
        continue;
      }
      madeLogins.add(
        Login(
          id: _placed(unit),
          name: name,
          username: username,
          password: password == null || password.isEmpty ? null : password,
          websites: rules.isEmpty ? null : fillHosts(rules),
          uris: rules.isEmpty ? null : rules,
          tags: tags,
          pinned: pinned,
          // The first login goes with the item's first code
          accountId: madeLogins.isEmpty && codes.isNotEmpty ? codes.first.id : null,
          passwordChangedAt: changedAt,
          source: document.exporterDisplayName,
          addedAt: addedAt,
        ),
      );
    }
    logins.addAll(madeLogins);

    final madePasskeys = <Passkey>[];
    for (final source in passkeySources) {
      final id = _placed(unit);
      final made = await readCxfPasskey(source, id: id, addedAt: addedAt, tags: tags);
      if (made.passkey == null) {
        unitOf.remove(id);
        skips.add(ImportSkip(skipTitle, made.skip!, detail: made.detail));
        continue;
      }
      madePasskeys.add(made.passkey!);
      if (made.extras) {
        notices.add(ImportNotice(skipTitle, NoticeReason.passkeyExtras));
      }
    }
    passkeys.addAll(madePasskeys);

    final madeCards = <PaymentCard>[];
    for (final source in cardSources) {
      final card = _card(source, _placed(unit), name, tags, pinned, addedAt);
      if (card == null) {
        skips.add(ImportSkip(skipTitle, SkipReason.unreadable, detail: 'credit-card'));
      } else {
        madeCards.add(card);
      }
    }
    cards.addAll(madeCards);

    final identityNote = <String>[];
    Identity? madeIdentity;
    if (names.isNotEmpty || addresses.isNotEmpty || documents.isNotEmpty) {
      madeIdentity = _identity(names, addresses, documents, identityNote, skipTitle, _placed(unit), name, tags, pinned, addedAt);
      identities.add(madeIdentity);
    }

    final madeKeys = <VaultKey>[];
    for (final source in sshSources) {
      final made = await readCxfSshKey(source, id: _placed(unit), name: name, addedAt: addedAt, tags: tags, pinned: item.favorite);
      if (made.key == null) {
        skips.add(ImportSkip(skipTitle, made.skip!));
      } else {
        madeKeys.add(made.key!);
      }
    }
    keys.addAll(madeKeys);

    // Notes and custom fields go into the note of the first thing the item became
    final text = [
      ...noteTexts,
      if (customLines.isNotEmpty) customLines.join('\n'),
      if (identityNote.isNotEmpty) identityNote.join('\n'),
    ].where((part) => part.trim().isNotEmpty).join('\n\n');
    if (text.isEmpty) {
      return;
    }
    if (madeLogins.isNotEmpty) {
      logins[logins.indexOf(madeLogins.first)] = madeLogins.first.copyWith(note: text);
    } else if (madeCards.isNotEmpty) {
      cards[cards.indexOf(madeCards.first)] = madeCards.first.copyWith(note: text);
    } else if (madeIdentity != null) {
      identities[identities.indexOf(madeIdentity)] = madeIdentity.copyWith(note: text);
    } else if (madeKeys.isNotEmpty) {
      keys[keys.indexOf(madeKeys.first)] = madeKeys.first.copyWith(note: text);
    } else if (madePasskeys.isNotEmpty) {
      passkeys[passkeys.indexOf(madePasskeys.first)] = madePasskeys.first.copyWith(note: text);
    } else if (codes.isNotEmpty) {
      accounts[accounts.indexOf(codes.first)] = codes.first.copyWith(note: text);
    } else {
      notes.add(SecureNote(id: _placed(unit), title: name, text: text, tags: tags, pinned: pinned, addedAt: addedAt));
    }
  }

  /// Why Kemlock can't make a code of [totp], or null when it can.
  SkipReason? _totpProblem(CxfTotp totp) {
    const algorithms = {'sha1', 'sha256', 'sha512'};
    if (!algorithms.contains(totp.algorithm)) {
      return SkipReason.totpAlgorithm;
    }
    if (totp.digits != 6 && totp.digits != 8) {
      return SkipReason.totpDigits;
    }
    final secret = normalizeSecret(totp.secret).replaceFirst(_trailingPadding, '');
    if (!_base32.hasMatch(secret) || base32Decode(secret).isEmpty) {
      return SkipReason.totpSecret;
    }
    if (totp.period <= 0 || totp.period > 86400) {
      return SkipReason.unreadable;
    }
    return null;
  }

  PaymentCard? _card(CxfCreditCard source, String id, String name, List<String>? tags, bool? pinned, int addedAt) {
    final digits = cardDigits(source.valueOf('number') ?? '');
    final cardholder = source.valueOf('fullName');
    if (digits.isEmpty && cardholder == null) {
      return null;
    }
    final expiry = _month(source.valueOf('expiryDate'));
    final validFrom = _month(source.valueOf('validFrom'));
    return PaymentCard(
      id: id,
      name: name,
      cardholder: cardholder,
      number: digits.isEmpty ? null : digits,
      brand: source.valueOf('cardType'),
      expMonth: expiry?.month,
      expYear: expiry?.year,
      code: source.valueOf('verificationNumber'),
      pin: source.valueOf('pin'),
      validFromMonth: validFrom?.month,
      validFromYear: validFrom?.year,
      tags: tags,
      pinned: pinned,
      source: document.exporterDisplayName,
      addedAt: addedAt,
    );
  }

  /// One identity from the item's name, first address and documents. What
  /// the identity has no place for goes into [note], one line each.
  Identity _identity(
    List<CxfPersonName> names,
    List<CxfAddress> addresses,
    List<CxfFielded> documents,
    List<String> note,
    String skipTitle,
    String id,
    String name,
    List<String>? tags,
    bool? pinned,
    int addedAt,
  ) {
    final person = names.isEmpty ? null : names.first;
    String? family;
    if (person != null) {
      final parts = [person.valueOf('surnamePrefix'), person.valueOf('surname'), person.valueOf('surname2')].nonNulls;
      family = parts.isEmpty ? null : parts.join(' ');
      for (final extra in ['givenInformal', 'credentials', 'generation']) {
        if (person.fields[extra] case final field? when field.value.trim().isNotEmpty) {
          note.add(_line(field.label ?? extra, field));
        }
      }
    }
    for (final other in names.skip(1)) {
      for (final field in other.fields.values) {
        if (field.value.trim().isNotEmpty) {
          note.add(_line(field.label, field));
        }
      }
    }

    IdentityAddress? address;
    String? phone;
    for (var i = 0; i < addresses.length; i++) {
      final source = addresses[i];
      if (i > 0) {
        final line = [
          for (final key in ['streetAddress', 'postalCode', 'city', 'territory', 'country']) source.valueOf(key),
        ].nonNulls.join(', ');
        if (line.isNotEmpty) {
          note.add(line);
        }
        continue;
      }
      final lines = [
        for (final line in (source.valueOf('streetAddress') ?? '').split('\n'))
          if (line.trim().isNotEmpty) line.trim(),
      ];
      address = IdentityAddress(
        // The model keeps three lines; a fourth joins the third
        lines: lines.isEmpty
            ? null
            : [
                ...lines.take(identityAddressLines - 1),
                if (lines.length >= identityAddressLines) lines.skip(identityAddressLines - 1).join(', '),
              ],
        city: source.valueOf('city'),
        region: source.valueOf('territory'),
        postalCode: source.valueOf('postalCode'),
        country: source.valueOf('country'),
      );
      phone = source.valueOf('tel');
    }

    final made = <IdentityDocument>[];
    String? birthDate;
    for (final source in documents) {
      final (IdentityDocumentType type, String? number, String? country) = switch (source) {
        CxfPassport() => (
          IdentityDocumentType.passport,
          source.valueOf('passportNumber') ?? source.valueOf('nationalIdentificationNumber'),
          source.valueOf('issuingCountry'),
        ),
        CxfDriversLicense() => (IdentityDocumentType.driversLicence, source.valueOf('licenseNumber'), source.valueOf('country')),
        _ => (
          IdentityDocumentType.idCard,
          source.valueOf('documentNumber') ?? source.valueOf('identificationNumber'),
          source.valueOf('issuingCountry'),
        ),
      };
      final born = _date(source.valueOf('birthDate'));
      birthDate ??= born;
      // What the identity has no place for, in the exporter's words
      for (final extra in ['nationality', 'birthPlace', 'sex', 'licenseClass', 'territory', 'fullName']) {
        if (extra == 'fullName' && person != null) {
          continue;
        }
        if (extra == 'territory' && source is! CxfDriversLicense) {
          continue;
        }
        if (source.fields[extra] case final field? when field.value.trim().isNotEmpty) {
          note.add(_line(field.label ?? extra, field));
        }
      }
      if (number == null) {
        skips.add(ImportSkip(skipTitle, SkipReason.unreadable, detail: (source as CxfCredential).type));
        continue;
      }
      made.add(
        IdentityDocument(
          id: newId(),
          type: type.wire,
          number: number,
          issuingCountry: country,
          issuingAuthority: source.valueOf('issuingAuthority'),
          issuedOn: _date(source.valueOf('issueDate')),
          expiresOn: _date(source.valueOf('expiryDate')),
        ),
      );
    }

    return Identity(
      id: id,
      name: name,
      title: person?.valueOf('title'),
      givenName: person?.valueOf('given'),
      middleName: person?.valueOf('given2'),
      familyName: family,
      phone: phone,
      birthDate: birthDate,
      address: address == null || address.isEmpty ? null : address,
      documents: made.isEmpty ? null : made,
      tags: tags,
      pinned: pinned,
      source: document.exporterDisplayName,
      addedAt: addedAt,
    );
  }
}

/// A field as a line of a note: `label: value`, a concealed one marked
/// `(secret)` so the person can move it.
String _line(String? label, CxfField field) {
  final text = label?.trim() ?? '';
  final named = field.concealed ? (text.isEmpty ? '(secret)' : '$text (secret)') : text;
  return named.isEmpty ? field.value : '$named: ${field.value}';
}

/// [tags] trimmed, without blanks or repeats, at most [_maxTags]; null for none.
List<String>? _tagList(Iterable<String> tags) {
  final unique = <String>{};
  for (final tag in tags) {
    final trimmed = tag.trim();
    if (trimmed.isNotEmpty && unique.length < _maxTags) {
      unique.add(trimmed);
    }
  }
  return unique.isEmpty ? null : unique.toList();
}

/// `YYYY-MM` as a month and a year; null for anything else.
({int month, int year})? _month(String? value) {
  final match = value == null ? null : _yearMonth.firstMatch(value);
  if (match == null) {
    return null;
  }
  final month = int.parse(match[2]!);
  return month >= 1 && month <= 12 ? (month: month, year: int.parse(match[1]!)) : null;
}

/// `YYYY-MM-DD` as it is; null for anything else.
String? _date(String? value) => value != null && _fullDate.hasMatch(value) ? value : null;
