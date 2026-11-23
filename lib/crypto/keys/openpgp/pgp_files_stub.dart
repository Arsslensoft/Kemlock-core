// The file operations of `pgp_files.dart` where there is no `dart:io`
// (dart2wasm): the browser reads and writes no files.

import 'dart:typed_data';

import 'pgp_error.dart';

const _unsupported = 'Files are not read or written in this build';

/// The size of the file at [path]: not possible in this build.
int pgpFileLength(String path) => throw UnsupportedError(_unsupported);

/// The size and head of the file at [path]: not possible in this build.
({int length, Uint8List head}) pgpFileHead(String path) => throw UnsupportedError(_unsupported);

/// Writes a file: not possible in this build.
void pgpWriteFile(String path, Uint8List bytes) => throw UnsupportedError(_unsupported);

/// Deletes a file: there is none to delete in this build.
void pgpDeleteFile(String path) {}

/// Moves a file: not possible in this build.
void pgpRenameFile(String from, String to) => throw UnsupportedError(_unsupported);

/// [name] in [directory], with a slash.
String pgpJoinPath(String directory, String name) => '$directory/$name';

/// No error is a file error in this build.
PgpException? pgpFileError(Object error) => null;
