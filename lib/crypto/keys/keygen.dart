// Making new key pairs, from the platform's secure random source, in a
// background isolate that Cancel kills: SSH, signing and exchange keys,
// and PGP keys (`openpgp/writer.dart`). Ed25519 and X25519 come from
// `cryptography`, ECDSA scalars from the random source, RSA from
// pointycastle's generator (`generateRsa` in `algorithms.dart`), ML-KEM and ML-DSA from `ml_kem.dart` and
// `ml_dsa.dart`. The result is the same ParsedKey an import gives.

import 'dart:async';
import 'dart:typed_data';

import '../background.dart';
import '../bytes.dart';
import 'algorithms.dart';
import 'der.dart';
import 'keys.dart';
import 'openpgp/edit.dart';
import 'openpgp/key_info.dart';
import 'openpgp/pgp_error.dart';
import 'openpgp/writer.dart';
import 'pkcs8.dart';

/// A key type the generate sheet offers.
enum GeneratedAlgorithm {
  ed25519(KeyAlgorithm.ed25519),
  ecdsaP256(KeyAlgorithm.ecdsaP256),
  ecdsaP384(KeyAlgorithm.ecdsaP384),
  rsa3072(KeyAlgorithm.rsa, 3072),
  rsa4096(KeyAlgorithm.rsa, 4096),
  x25519(KeyAlgorithm.x25519),
  mlKem768(KeyAlgorithm.mlKem768),
  mlKem1024(KeyAlgorithm.mlKem1024),
  mlDsa65(KeyAlgorithm.mlDsa65);

  const GeneratedAlgorithm(this._algorithm, [this.bits]);

  final KeyAlgorithm _algorithm;

  /// The RSA modulus size.
  final int? bits;

  /// The name `VaultKey.algorithm` stores: `ed25519`, `rsa`, ...
  String get id => _algorithm.id;
}

/// What each kind offers, the default first (the spec's "Generate a key
/// pair on the phone").
const Map<KeyKind, List<GeneratedAlgorithm>> generatedAlgorithms = {
  KeyKind.ssh: [GeneratedAlgorithm.ed25519, GeneratedAlgorithm.ecdsaP256, GeneratedAlgorithm.rsa3072, GeneratedAlgorithm.rsa4096],
  KeyKind.signing: [
    GeneratedAlgorithm.ed25519,
    GeneratedAlgorithm.ecdsaP256,
    GeneratedAlgorithm.ecdsaP384,
    GeneratedAlgorithm.rsa3072,
    GeneratedAlgorithm.rsa4096,
    GeneratedAlgorithm.mlDsa65,
  ],
  KeyKind.exchange: [GeneratedAlgorithm.x25519, GeneratedAlgorithm.mlKem768, GeneratedAlgorithm.mlKem1024],
};

/// What to make.
sealed class KeyRequest {
  const KeyRequest();
}

/// An SSH, signing or exchange key of [algorithm], one of
/// [generatedAlgorithms] for its [kind].
final class NewKeyRequest extends KeyRequest {
  const NewKeyRequest(this.kind, this.algorithm);

  final KeyKind kind;
  final GeneratedAlgorithm algorithm;
}

/// A PGP key for [name] and [email], whose user ID is `Name <email>`: an
/// EdDSA key with a Curve25519 subkey unless [type] says otherwise, which
/// expires [expiresInYears] years after it is made, or never when null.
final class PgpKeyRequest extends KeyRequest {
  const PgpKeyRequest({required this.name, required this.email, this.type = PgpKeyType.ed25519, this.expiresInYears});

  final String name;
  final String email;
  final PgpKeyType type;
  final int? expiresInYears;
}

/// The same day and time [years] years after [created], in UTC; 29
/// February goes to 1 March in a year without one.
DateTime yearsAfter(DateTime created, int years) {
  final t = created.toUtc();
  return DateTime.utc(t.year + years, t.month, t.day, t.hour, t.minute, t.second);
}

/// A change to the PGP key [secretKey] (`openpgp/edit.dart`), signed by its
/// primary key, opened with [passphrase] when it keeps one, at [now]: made
/// in the same cancellable isolate, since a new RSA subkey takes seconds.
/// Its result is the changed key; a [PgpEditException] or [PgpException]
/// it throws comes back as the error of [KeyGeneration.result].
final class PgpChangeRequest extends KeyRequest {
  const PgpChangeRequest(this.secretKey, this.change, {this.passphrase, required this.now});

  final Uint8List secretKey;
  final PgpChange change;
  final String? passphrase;
  final DateTime now;
}

/// How a generation ended.
sealed class KeyGenerationResult {
  const KeyGenerationResult();
}

final class KeyGenerated extends KeyGenerationResult {
  const KeyGenerated(this.key);

  final ParsedKey key;
}

/// Cancelled, or stopped because the vault locked: nothing was made.
final class KeyGenerationCancelled extends KeyGenerationResult {
  const KeyGenerationCancelled();
}

/// Starts making a key in a background isolate. Throws an [ArgumentError]
/// at once for a request the generate sheet wouldn't make: an algorithm
/// its kind doesn't offer, or a PGP key without a name or an email (the
/// error's `name` says which).
KeyGeneration generateKey(KeyRequest request) {
  _checkRequest(request);
  return KeyGeneration._(request);
}

/// A key being made in a background isolate. [result] completes with
/// [KeyGenerated], or with [KeyGenerationCancelled] once [cancel] kills the
/// isolate, so nothing of the unfinished key is left; it completes with an
/// error only if the generation itself failed.
class KeyGeneration {
  KeyGeneration._(KeyRequest request) {
    unawaited(_start(request));
  }

  final _done = Completer<KeyGenerationResult>();
  BackgroundJob<Object>? _job;

  Future<KeyGenerationResult> get result => _done.future;

  /// Stops the generation; does nothing once it has finished.
  void cancel() {
    if (_done.isCompleted) return;
    _done.complete(const KeyGenerationCancelled());
    _job?.cancel();
  }

  Future<void> _start(KeyRequest request) async {
    try {
      final job = _job = startBackgroundJob<Object>(_generator(request));
      final message = await job.result;
      if (_done.isCompleted) return;
      switch (message) {
        case ParsedKey():
          _done.complete(KeyGenerated(message));
        case final Exception error when error is PgpEditException || error is PgpException || error is KeyFormatException:
          _done.completeError(error);
        default:
          _done.completeError(StateError('key generation stopped without a key'));
      }
    } on BackgroundError catch (e) {
      if (!_done.isCompleted) _done.completeError(StateError('key generation failed: ${e.error}'), StackTrace.fromString(e.stack));
    } on BackgroundStopped {
      if (!_done.isCompleted) _done.completeError(StateError('key generation stopped without a key'));
    } on Object catch (e, stack) {
      if (!_done.isCompleted) _done.completeError(e, stack);
    }
  }
}

/// The computation for the background isolate, made apart from [KeyGeneration] so that it captures the request and not the generation
/// (which holds a completer and cannot be sent).
Future<Object> Function() _generator(KeyRequest request) =>
    () => _generate(request);

/// What the background isolate runs: the key, or the exception that says
/// why there is none, to give back as a value.
Future<Object> _generate(KeyRequest request) async {
  try {
    return await makeKey(request);
  } on PgpEditException catch (e) {
    return e;
  } on PgpException catch (e) {
    return e;
  } on KeyFormatException catch (e) {
    return e;
  }
}

/// Makes the key on the calling isolate. [generateKey] runs this in the
/// background; tests and fakes call it directly.
Future<ParsedKey> makeKey(KeyRequest request) async {
  _checkRequest(request);
  switch (request) {
    case NewKeyRequest(:final kind, :final algorithm):
      final material = await _material(algorithm);
      return ParsedKey(
        kind: kind,
        algorithm: algorithm.id,
        bits: algorithm.bits,
        private: writePkcs8(material),
        public: writeSpki(material.publicHalf!),
      );
    case PgpKeyRequest(:final name, :final email, :final type, :final expiresInYears):
      // Whole seconds, as the key keeps its creation time
      final created = DateTime.fromMillisecondsSinceEpoch(DateTime.now().millisecondsSinceEpoch ~/ 1000 * 1000, isUtc: true);
      final expirySeconds = expiresInYears == null ? null : yearsAfter(created, expiresInYears).difference(created).inSeconds;
      final secret = await generatePgpKey(userId: pgpUserId(name, email), type: type, created: created, expirySeconds: expirySeconds);
      // Kemlock checks its own signatures before anyone else has to.
      await checkSelfSignatures(secret);
      final key = readTransferableKey(secret);
      return ParsedKey(kind: KeyKind.pgp, algorithm: 'pgp', private: secret, public: transferablePublicKey(key.packets), pgp: key.info);
    case PgpChangeRequest(:final secretKey, :final change, :final passphrase, :final now):
      final changed = await changePgpKey(secretKey, change, passphrase: passphrase, now: now);
      final key = readTransferableKey(changed);
      return ParsedKey(kind: KeyKind.pgp, algorithm: 'pgp', private: changed, public: transferablePublicKey(key.packets), pgp: key.info);
  }
}

void _checkRequest(KeyRequest request) {
  switch (request) {
    case NewKeyRequest(:final kind, :final algorithm):
      if (!(generatedAlgorithms[kind]?.contains(algorithm) ?? false)) {
        throw ArgumentError('a ${kind.name} key is not made with ${algorithm.name}');
      }
    case PgpKeyRequest(:final name, :final email, :final expiresInYears):
      pgpUserId(name, email);
      if (expiresInYears != null && expiresInYears < 1) throw ArgumentError.value(expiresInYears, 'expiresInYears', 'must be 1 or more');
    case PgpChangeRequest(:final change):
      if (change case AddPgpUserId(:final name, :final email)) pgpUserId(name, email);
  }
}

Future<KeyMaterial> _material(GeneratedAlgorithm algorithm) async {
  switch (algorithm) {
    case GeneratedAlgorithm.ed25519:
      return ed25519Material(randomBytes(32));
    case GeneratedAlgorithm.x25519:
      return x25519Material(randomBytes(32));
    case GeneratedAlgorithm.ecdsaP256 || GeneratedAlgorithm.ecdsaP384:
      final curve = algorithm == GeneratedAlgorithm.ecdsaP256 ? EcCurve.p256 : EcCurve.p384;
      return ecMaterial(curve, _ecScalar(curve));
    case GeneratedAlgorithm.rsa3072 || GeneratedAlgorithm.rsa4096:
      return generateRsa(algorithm.bits!);
    case GeneratedAlgorithm.mlKem768:
      return pqMaterial(PqParameters.mlKem768, seed: randomBytes(64));
    case GeneratedAlgorithm.mlKem1024:
      return pqMaterial(PqParameters.mlKem1024, seed: randomBytes(64));
    case GeneratedAlgorithm.mlDsa65:
      return pqMaterial(PqParameters.mlDsa65, seed: randomBytes(32));
  }
}

/// A scalar in [1, n - 1], drawn until one falls there (for P-256 and
/// P-384, nearly always the first).
Uint8List _ecScalar(EcCurve curve) {
  final n = curve.domain.n;
  while (true) {
    final d = randomBytes(curve.size);
    final value = bytesToBigInt(d);
    if (value > BigInt.zero && value < n) return d;
  }
}
