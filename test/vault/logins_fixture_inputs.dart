// What the login fixtures of test/fixtures/logins hold (openspec:
// add-passwords, task 7.7), shared by the generator that wrote them once and
// the tests that open them. Never change these: the fixtures were written
// from them and are frozen.
import 'package:kemlock_core/models/generated_password.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';

const loginsFixturePassword = 'fixture password';

final loginsFixtureWrittenAt = DateTime.utc(2026, 11, 21, 12);

const loginsFixtureAccount = OtpAccount(
  id: '3b9e2f4a-6c1d-4e8b-a07f-5d2c9e1b4a63',
  issuer: 'Larkspur Mail',
  label: 'ada@example.org',
  secret: 'JBSWY3DPEHPK3PXP',
  addedAt: 1795300000000,
);

/// A login with every field: linked to the account, its password changed
/// twice, saved by AutoFill, told not to warn for its code, and a key of a
/// later version, which must pass through.
final loginsFixtureMail = Login.fromJson({
  'id': '8d4f2a1c-9e3b-4c7d-b6a5-2f1e0d9c8b74',
  'name': 'Larkspur Mail',
  'username': 'ada@example.org',
  'password': 'Hw7e%Ns3Ry_bX5tK?pM8a',
  'websites': ['mail.larkspur.example', 'larkspur.example'],
  'note': 'Recovery email is the work one',
  'tags': ['mail', 'personal'],
  'pinned': true,
  'accountId': '3b9e2f4a-6c1d-4e8b-a07f-5d2c9e1b4a63',
  'passwordChangedAt': 1795300120000,
  'previousPasswords': [
    {'password': 'one-two-three', 'until': 1795300120000},
    {'password': 'first password', 'until': 1795300060000},
  ],
  'codeWarning': false,
  'source': 'autofill',
  'addedAt': 1795300000000,
  'updatedAt': 1795300120000,
  'later': {'what': 'a key a later version writes', 'kept': true},
});

/// A login saved in an app: a name and a password, no website.
const loginsFixtureApp = Login(
  id: '0c6e8a2b-4d1f-4a9e-8b3c-7e5d1f0a2c96',
  name: 'Banking app',
  username: 'ada',
  password: '4815 1623',
  addedAt: 1795300180000,
);

/// A login of the shared space `fam`.
const loginsFixtureShared = Login(
  id: '5a1d3f7b-2e9c-4b6a-9d8e-1c0f2b4a6e38',
  name: 'Family streaming',
  username: 'family@example.org',
  password: 'kT9#vq2L-wPz8!mR4x',
  websites: ['=10.0.0.20', 'stream.example'],
  spaceId: 'fam',
  addedAt: 1795300240000,
);

/// A deleted login's tombstone in the vault's own file.
const loginsFixtureDeleted = {'id': 'e7b2c4d6-8f0a-4c1e-a3b5-9d7f1e3c5a02', 'at': 1795300300000};

/// A password AutoFill generated that no save followed.
const loginsFixtureGenerated = GeneratedPassword(password: 'Qz4!rN8-xB2#vL6?mK1w', site: 'shop.example', at: 1795300360000);
