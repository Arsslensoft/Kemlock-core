// What the card and identity fixtures of test/fixtures/cards hold (the
// add-cards-identities-and-websites plan, tasks 2.2, 3.3 and 3.5), shared by
// the generator that writes them once and the tests that open them. Never
// change these once the fixtures are written from them.
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/payment_card.dart';

const cardsFixturePassword = 'fixture password';

final cardsFixtureWrittenAt = DateTime.utc(2026, 11, 21, 12);

const cardsFixtureAccount = OtpAccount(
  id: '3b9e2f4a-6c1d-4e8b-a07f-5d2c9e1b4a63',
  issuer: 'Larkspur Mail',
  label: 'ada@example.org',
  secret: 'JBSWY3DPEHPK3PXP',
  addedAt: 1795300000000,
);

/// A card with every field and a key of a later version, which must pass through.
final cardsFixtureVisa = PaymentCard.fromJson({
  'id': '2f6a8c1e-5b3d-4a7f-9e0c-8d4b1a6c3e57',
  'name': 'Everyday Visa',
  'cardholder': 'Ada Lovelace',
  'number': '4111111111111111',
  'brand': 'Visa',
  'expMonth': 5,
  'expYear': 2029,
  'code': '123',
  'pin': '4321',
  'validFromMonth': 6,
  'validFromYear': 2024,
  'note': 'Joint account',
  'tags': ['bank', 'personal'],
  'pinned': true,
  'source': 'import',
  'addedAt': 1795300000000,
  'updatedAt': 1795300120000,
  'later': {'what': 'a key a later version writes', 'kept': true},
});

/// A card with a name and a cardholder only.
const cardsFixtureMinimal = PaymentCard(
  id: '9c3e5a7b-1d2f-4b8a-a6c4-0e7f2d9b1a35',
  name: 'Gift card',
  cardholder: 'Ada Lovelace',
  addedAt: 1795300180000,
);

/// A card of the shared space `fam`.
const cardsFixtureShared = PaymentCard(
  id: '6d8f0b2c-4e1a-4c3b-8a5d-3f9e7c1b0a24',
  name: 'Family Mastercard',
  number: '5555555555554444',
  brand: 'Mastercard',
  expMonth: 12,
  expYear: 2027,
  spaceId: 'fam',
  addedAt: 1795300240000,
);

/// An identity with every field, two documents, and keys of a later version at each level.
final cardsFixtureMe = Identity.fromJson({
  'id': '4a1c7e9d-3b5f-4d2a-b8e6-6f0a2c4d8b19',
  'name': 'Me',
  'title': 'Countess',
  'givenName': 'Ada',
  'middleName': 'Augusta',
  'familyName': 'Lovelace',
  'company': 'Analytical Engines',
  'email': 'ada@example.org',
  'phone': '+44 20 7946 0000',
  'username': 'ada',
  'birthDate': '1815-12-10',
  'address': {
    'lines': ['1 Example Road', 'Flat 2'],
    'city': 'London',
    'region': 'England',
    'postalCode': 'N1 1AA',
    'country': 'GB',
    'later': 'an address key of a later version',
  },
  'documents': [
    {
      'id': 'b2d4f6a8-0c1e-4a3b-9d5f-7e9a1c3b5d07',
      'type': 'passport',
      'number': '123456789',
      'issuingCountry': 'GB',
      'issuingAuthority': 'HM Passport Office',
      'issuedOn': '2021-03-15',
      'expiresOn': '2031-03-14',
    },
    {'id': 'c5e7a9b1-2d3f-4b6c-8e0a-1f3d5b7c9e41', 'type': 'residencePermit', 'number': 'RP-77', 'later': true},
  ],
  'note': 'For travel forms',
  'tags': ['personal'],
  'pinned': true,
  'addedAt': 1795300000000,
  'updatedAt': 1795300120000,
  'later': {'what': 'a key a later version writes', 'kept': true},
});

/// An identity with a name and an email only.
const cardsFixtureWork = Identity(
  id: 'd7f9b1c3-4e5a-4c8d-a0b2-3a5c7e9f1b63',
  name: 'Work',
  email: 'ada@work.example',
  addedAt: 1795300180000,
);

/// An identity of the shared space `fam`.
const cardsFixtureFamily = Identity(
  id: 'e9a1c3d5-6f7b-4e0a-b2c4-5c7e9a1d3f85',
  name: 'Family address',
  address: IdentityAddress(lines: ['2 Example Road'], city: 'Leeds', country: 'GB'),
  spaceId: 'fam',
  addedAt: 1795300240000,
);

/// A deleted card's tombstone in the vault's own sync file.
const cardsFixtureDeleted = {'id': 'f1b3d5e7-8a9c-4f2b-a4d6-7e9b1c3f5a07', 'at': 1795300300000};
