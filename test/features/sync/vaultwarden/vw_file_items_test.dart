@TestOn('vm')
library;

// Vaultwarden has no File type: a File item stays on this phone, and a run never uploads it, deletes it or drops it.
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';
import 'vw_kit.dart';

const _file = VaultFile(
  id: '3f2c9a71-e4b0-4856-8a00-0000000000f1',
  name: 'Lease.pdf',
  file: NoteAttachment(
    id: 'att-1',
    name: 'Lease.pdf',
    size: 10,
    key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    addedAt: 1,
    sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  ),
  addedAt: 1,
);

const _account = OtpAccount(id: 'a1', issuer: 'GitHub', label: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);

void main() {
  test('a run leaves File items on the phone, sends nothing of them, and the codes still sync', () async {
    final server = FakeVaultwarden();
    final target = await makeHome(server, VaultwardenMode.sealed);
    final scope = VaultwardenScopeSync(
      connection: VwConnection(
        api: VwApi(server.client),
        server: FakeVaultwarden.url,
        credentials: server.credentials(),
        onCredentials: (_) async {},
      ),
      reader: VwReader(server.userKey),
      target: target,
    );
    var lists = const Lists(accounts: [_account], files: [_file]);
    var state = const ScopeState(known: []);

    for (var run = 1; run <= 2; run++) {
      final at = server.revision + 500;
      final result = await scope.sync(lists, state, now: at);
      lists = applyScope(lists, null, result.doc);
      state = ScopeState(known: result.known, lastSyncAt: at, extra: result.state);

      expect(lists.files, [_file], reason: 'run $run: kept as it was');
      expect(lists.accounts, hasLength(1));
      expect(result.doc.files, [_file]);
    }

    // Nothing of the File item reached the server: the home and the code's item are all there is
    final text = server.ciphers.values.map((cipher) => cipher.toString()).join();
    expect(text, isNot(contains('Lease.pdf')));
    expect(state.known, isNot(contains(_file.id)), reason: 'a deletion of it is never recorded');
  });
}
