@TestOn('vm')
library;

// File items in the duplicate finder (crypto.md, "Duplicate tags": the `file` tag).
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/dedup.dart';
import 'package:kemlock_core/features/duplicates/dedup_cache.dart';
import 'package:kemlock_core/features/duplicates/dedup_tagger.dart';
import 'package:kemlock_core/features/duplicates/duplicate_matcher.dart';
import 'package:kemlock_core/features/duplicates/duplicate_merge.dart';
import 'package:kemlock_core/features/duplicates/duplicate_rules.dart';
import 'package:kemlock_core/features/duplicates/duplicate_tags.dart';
import 'package:kemlock_core/features/duplicates/duplicate_view.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:test/test.dart';

const _hash = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

VaultFile _file(String id, {String? sha256 = _hash, String name = 'Lease.pdf', int at = 1}) => VaultFile(
  id: id,
  name: name,
  file: NoteAttachment(id: 'att-$id', name: name, size: 10, key: 'k', addedAt: 1, sha256: sha256),
  addedAt: at,
);

String _hex(List<int> bytes) => [for (final byte in bytes) byte.toRadixString(16).padLeft(2, '0')].join();

void main() {
  group('the file tag', () {
    test('is made over the content hash in lower case, as the server vector has it', () {
      // test-vectors/dedup-normalise.json, "file-upper-case-hash"
      final key = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final input = fileTagInput(_file('a', sha256: ' ${_hash.toUpperCase()} '));

      expect(input!.array, ['file', _hash]);
      expect(jsonEncode(input.array), '["file","$_hash"]');
      expect(_hex(dedupTag(key, 'file', input.values)), '375689fe79d3db9294744e6e9d981a1a72480eba53567c52f06d0c7c9dd5460a');
      expect(itemTags(_file('a'), key).single.kind, TagKind.file);
    });

    test('is none for a file without a hash, or with something that is not one', () {
      expect(fileTagInput(_file('a', sha256: null)), isNull);
      expect(fileTagInput(_file('a', sha256: 'sha256:abc')), isNull);
      expect(tagInputsOf(_file('a', sha256: null)), isEmpty);
    });
  });

  group('the finder', () {
    List<DuplicateGroup> find(List<VaultFile> files) {
      final items = dedupItems(files: files);
      final cache = DedupCache.fresh('list');
      final result = refreshTags(cache, items, dedupOwners(cache, const []));
      return findDuplicates(items: items, tags: {for (final MapEntry(:key, :value) in result.cache.owners.entries) key: value.items});
    }

    test('groups File items with one hash, whatever their names, with the reason sameFile', () {
      final groups = find([_file('a'), _file('b', name: 'Copy of lease.pdf'), _file('c', sha256: '1' * 64), _file('d', sha256: null)]);

      expect(groups, hasLength(1));
      expect(groups.single.reason, DuplicateReason.sameFile);
      expect(groups.single.items.map((item) => item.id).toList()..sort(), ['a', 'b']);
      expect(duplicateName(groups.single.items.first.item), 'Lease.pdf');
    });

    test('sameFile and sameCredential tell the same file by hash or id', () {
      expect(sameFile(_file('a'), _file('b')), isTrue);
      expect(sameFile(_file('a'), _file('a', sha256: null)), isTrue);
      expect(sameFile(_file('a'), _file('b', sha256: '1' * 64)), isFalse);
      expect(sameFile(_file('a', sha256: null), _file('b', sha256: null)), isFalse);
      expect(sameCredential(_file('a'), _file('b')), isTrue);
    });
  });

  group('a merge', () {
    test('keeps the newest File item, takes the name picked, and reads and writes the record as a file', () {
      final older = _file('a', name: 'lease.pdf', at: 1);
      final newer = _file('b', name: 'Lease 2026.pdf', at: 5);
      final choices = MergeChoices(dedupItems(files: [older, newer]));

      expect(choices.keptId, 'b');
      final merged = choices.merged(10) as VaultFile;
      expect(merged.name, 'Lease 2026.pdf');
      expect(mergeKindOf(merged), 'file');
      expect(mergeItemOf('file', mergeJsonOf(merged)), merged);
    });
  });
}
