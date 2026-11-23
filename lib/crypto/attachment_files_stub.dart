// The file helpers of `attachment_files.dart` where there is no `dart:io`
// (dart2wasm): the browser never reads or writes an attached file.

library;

import 'dart:typed_data';

/// Encrypts [plain] to the file at [path]: not possible in this build.
Future<void> kma1EncryptToFile(Uint8List plain, Uint8List key, String path) =>
    Future<void>.error(UnsupportedError('Attached files are not read or written in this build'));

/// Decrypts the `KMA1` file at [input] to [output]: not possible in this build.
Future<void> kma1DecryptFile(String input, String output, Uint8List key) =>
    Future<void>.error(UnsupportedError('Attached files are not read or written in this build'));
