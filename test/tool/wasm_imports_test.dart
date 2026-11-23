@TestOn('vm')
library;

import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:test/test.dart';

/// The account crypto and the OPAQUE client run in the browser extension's dart2wasm core
/// (docs/plans/add-account-crypto.md, task 6.4; add-browser-extension, tasks 2.3 and 2.6). A library there
/// can't reach `dart:io`, `dart:ffi` or `dart:isolate`, or Flutter, through any import, however far down the
/// chain. A conditional import whose condition is `dart.library.io` is the one way in: the io file is only
/// compiled where there is an io library, and its stub stands in under wasm.
///
/// This reads the imports of those libraries and everything they import, from the files themselves. It is
/// what a VM test can check; `dart test -p chrome -c dart2wasm -t wasm` is what compiles them.
const _forbiddenLibraries = ['dart:io', 'dart:ffi', 'dart:isolate', 'dart:mirrors', 'dart:ui', 'dart:html', 'dart:js', 'dart:js_util'];

/// The packages the wasm-bound libraries may use, which all compile to wasm.
const _allowedPackages = {'crypto', 'cryptography', 'unorm_dart', 'collection', 'meta', 'typed_data'};

/// The libraries that must compile under dart2wasm, the roots of the walk: the account crypto, the OPAQUE
/// client and the fingerprint helpers of the spaces plan.
const _roots = ['lib/crypto/account', 'lib/crypto/opaque', 'lib/features/spaces/fingerprint.dart'];

final _directive = RegExp(r'^(?:import|export)\s+[^;]+;', multiLine: true);
final _firstUri = RegExp('''['"]([^'"]+)['"]''');
final _conditional = RegExp('''if\\s*\\(([^)]*)\\)\\s*['"]([^'"]+)['"]''');

typedef _Reach = ({Map<String, Set<String>> edges, List<String> problems});

/// Every file reached from [_roots] through unconditional imports and exports, with what each one imports.
_Reach _walk() {
  final queue = <String>[];
  for (final root in _roots) {
    if (FileSystemEntity.isDirectorySync(root)) {
      queue.addAll(Directory(root).listSync(recursive: true).whereType<File>().map((f) => p.normalize(f.path)));
    } else {
      queue.add(p.normalize(root));
    }
  }
  final edges = <String, Set<String>>{};
  final problems = <String>[];
  while (queue.isNotEmpty) {
    final file = queue.removeLast();
    if (!file.endsWith('.dart') || edges.containsKey(file)) {
      continue;
    }
    final next = edges[file] = <String>{};
    if (!File(file).existsSync()) {
      continue;
    }
    final text = File(file).readAsStringSync();
    for (final directive in _directive.allMatches(text).map((m) => m.group(0)!)) {
      final uri = _firstUri.firstMatch(directive)!.group(1)!;
      // `if (dart.library.io) 'x_io.dart'` is the branch that needs io: it is left out of the walk, and its
      // stub, the main uri, stands in under wasm. Any other condition (js_interop and so on) is walked.
      final targets = [
        uri,
        for (final match in _conditional.allMatches(directive))
          if (!match.group(1)!.contains('dart.library.io')) match.group(2)!,
      ];
      for (final target in targets) {
        if (target.startsWith('dart:')) {
          if (_forbiddenLibraries.contains(target)) {
            problems.add('$file imports $target');
          }
        } else if (target.startsWith('package:')) {
          final package = target.substring('package:'.length).split('/').first;
          if (package == 'kemlock' || package == 'kemlock_core') {
            next.add(p.normalize(p.join('lib', target.substring('package:$package/'.length))));
          } else if (!_allowedPackages.contains(package)) {
            problems.add('$file imports package:$package, which is not known to compile under dart2wasm');
          }
        } else {
          next.add(p.normalize(p.join(p.dirname(file), target)));
        }
      }
    }
    queue.addAll(next);
  }
  return (edges: edges, problems: problems);
}

void main() {
  final reach = _walk();

  test('the walk reaches the files it is meant to hold to', () {
    final files = reach.edges.keys.map((f) => f.replaceAll(r'\', '/')).toSet();
    expect(
      files,
      containsAll([
        'lib/crypto/account/argon2id.dart',
        'lib/crypto/account/send.dart',
        'lib/crypto/account/sealed_box.dart',
        'lib/crypto/opaque/opaque_client.dart',
        'lib/crypto/attachment_core.dart',
        'lib/crypto/background.dart',
        'lib/crypto/background_stub.dart',
        'lib/crypto/ml_kem.dart',
        'lib/crypto/ml_dsa.dart',
      ]),
    );
    // The io half of the conditional import is out of the walk, with the Isolate it holds
    expect(files, isNot(contains('lib/crypto/background_io.dart')));
    expect(files, isNot(contains('lib/crypto/attachment_files.dart')));
  });

  test('no account or OPAQUE library reaches dart:io, dart:ffi, dart:isolate or Flutter', () {
    expect(reach.problems, isEmpty);
  });

  test('every file the walk reaches exists', () {
    final missing = [
      for (final entry in reach.edges.entries)
        for (final target in entry.value)
          if (!File(target).existsSync()) '${entry.key} imports $target, which is not there',
    ];
    expect(missing, isEmpty);
  });
}
