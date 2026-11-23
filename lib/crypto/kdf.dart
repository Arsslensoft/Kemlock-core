// Key derivation off the UI isolate. scrypt at the vault's N=2^17 and
// PBKDF2 at the QR export's 200,000 rounds each take a noticeable moment,
// so they run in a short-lived isolate (`runInBackground`) and the UI keeps
// moving; noble runs them on the main thread in the TypeScript app.

import 'dart:typed_data';

import 'background.dart';
import 'pbkdf2.dart';
import 'scrypt.dart';

/// [scrypt] in a background isolate. The key comes back without a copy;
/// argument errors are rethrown here.
Future<Uint8List> scryptInBackground(
  List<int> password,
  List<int> salt, {
  required int n,
  required int r,
  required int p,
  int length = 32,
}) {
  final passwordBytes = Uint8List.fromList(password);
  final saltBytes = Uint8List.fromList(salt);
  return runInBackground(
    () => scrypt(passwordBytes, saltBytes, n: n, r: r, p: p, length: length),
    debugName: 'scrypt',
  );
}

/// [pbkdf2Sha256] in a background isolate.
Future<Uint8List> pbkdf2Sha256InBackground(List<int> password, List<int> salt, int iterations, int length) {
  final passwordBytes = Uint8List.fromList(password);
  final saltBytes = Uint8List.fromList(salt);
  return runInBackground(() => pbkdf2Sha256(passwordBytes, saltBytes, iterations, length), debugName: 'pbkdf2');
}
