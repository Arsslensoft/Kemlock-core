import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/scrypt.dart';

/// scrypt with tiny parameters, so behaviour tests don't spend a quarter of
/// a second per password. The real parameters are checked against the
/// v0.1.0 fixture in legacy_test.dart.
Future<Uint8List> fastKdf(String password, Uint8List salt) async => scrypt(utf8.encode(password), salt, n: 16, r: 1, p: 1);
