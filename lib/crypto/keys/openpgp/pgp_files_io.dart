// The file operations of `pgp_files.dart` where there is a `dart:io`.

import 'dart:io';
import 'dart:typed_data';

import 'pgp_error.dart';
import 'stream.dart';

/// The size of the file at [path].
int pgpFileLength(String path) => File(path).lengthSync();

/// The size of the file at [path] and its first [pgpPieceSize] bytes. A file
/// that can't be read is [PgpProblem.damaged].
({int length, Uint8List head}) pgpFileHead(String path) {
  final file = File(path);
  final int length;
  final Uint8List head;
  try {
    length = file.lengthSync();
    final handle = file.openSync();
    try {
      head = handle.readSync(pgpPieceSize);
    } finally {
      handle.closeSync();
    }
  } on FileSystemException catch (e) {
    throw PgpException(PgpProblem.damaged, detail: e.message);
  }
  return (length: length, head: head);
}

/// Writes [bytes] to the file at [path] and flushes it.
void pgpWriteFile(String path, Uint8List bytes) => File(path).writeAsBytesSync(bytes, flush: true);

/// Deletes the file at [path] if it is there; a file that can't be deleted is left.
void pgpDeleteFile(String path) {
  try {
    final file = File(path);
    if (file.existsSync()) file.deleteSync();
  } on FileSystemException {
    // The job's directory is deleted whole afterwards
  }
}

/// Moves the file at [from] to [to].
void pgpRenameFile(String from, String to) => File(from).renameSync(to);

/// [name] in [directory], with the platform's separator.
String pgpJoinPath(String directory, String name) => '$directory${Platform.pathSeparator}$name';

/// The [PgpProblem.outOfSpace] exception for a file error, or null for an error that is not one.
PgpException? pgpFileError(Object error) =>
    error is FileSystemException ? PgpException(PgpProblem.outOfSpace, detail: error.message) : null;
