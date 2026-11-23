// A space's chain routes on Kemlock Server (the space chain section of docs/crypto.md, "What the server stores, serves
// and checks"), all under `/kem/v1/spaces/{id}/chain`:
//
// - `GET` answers the whole chain as an array of wire-form records, and `GET ?from=n` the records with `seq >= n`;
// - `GET /{seq}/seals` answers the seal hashes record `seq` committed;
// - `POST` appends 1 to 16 records with the boxes and sealed names their commitments cover, and the live items a key
//   replacement names held: `201 {link, seq}`, `409 {head}` when the head moved (read the chain again and rebuild the
//   record), `422 {reason, seq}` when verification refuses a record.
//
// Only the home takes the `POST`. A client never trusts what the `GET` answers: `space_verify.dart` checks the whole
// chain, and the head this device accepted is the anchor.
//
// Pure Dart, no Flutter.

library;

import '../../crypto/account/encoding.dart';
import '../sync/kemlock/km_api.dart';
import 'space_chain.dart';
import 'space_seals.dart';

/// The most records one append carries.
const maxAppendRecords = 16;

/// What the server answers an append with: the link of the new head and its `seq`.
typedef ChainAppended = ({String link, int seq});

/// Why an append wasn't taken.
enum ChainAppendFailure {
  /// The head moved while the record was made: read the chain again and build the record again.
  headMoved,

  /// The server's verification refused a record, for [ChainAppendError.problem].
  refused,
}

/// An append the server didn't take.
class ChainAppendError implements Exception {
  const ChainAppendError(this.failure, {this.problem, this.reason, this.seq, this.head});

  final ChainAppendFailure failure;

  /// For [ChainAppendFailure.refused]: the chain's reason, when the server's words are one of them.
  final ChainProblem? problem;

  /// The server's own word for the reason.
  final String? reason;

  /// For [ChainAppendFailure.refused]: the `seq` of the record it refused.
  final int? seq;

  /// For [ChainAppendFailure.headMoved]: the head the server holds, as it sent it.
  final Object? head;

  @override
  String toString() => 'ChainAppendError(${failure.name}${reason != null ? ': $reason' : ''}${seq != null ? ' at $seq' : ''})';
}

/// The reason of a 422 as the chain's [ChainProblem], whatever its spelling (`too-large`, `tooLarge`, `too large`), or
/// null when it is not one of them.
ChainProblem? chainProblemOf(String? reason) {
  if (reason == null) {
    return null;
  }
  final plain = reason.toLowerCase().replaceAll(RegExp(r'[^a-z]'), '');
  for (final problem in ChainProblem.values) {
    if (problem.name.toLowerCase() == plain) {
      return problem;
    }
  }
  return null;
}

/// One space's chain routes on one server, through a connection that keeps the access token alive.
class SpaceChainClient {
  SpaceChainClient({required this.connection, required this.server, required this.space});

  final KmConnection connection;
  final Uri server;
  final String space;

  KmApi get _api => connection.api;

  /// The records with `seq >= from` (all of them by default), as the server sent them. A body that isn't a list of
  /// records is a [ChainRefusal] of [ChainProblem.malformed] or [ChainProblem.tooLarge], from [parseChain].
  Future<List<SignedChainEntry>> read({int from = 0}) async {
    if (from < 0) {
      throw ArgumentError.value(from, 'from', 'a sequence number from 0');
    }
    final query = from == 0 ? null : {'from': '$from'};
    final raw = await connection.call((token) => _api.callValue('GET', server, '/spaces/$space/chain', token: token, query: query));
    return parseChain(raw);
  }

  /// The seal hashes the record at [seq] committed.
  Future<List<ChainSealHash>> sealHashes(int seq) async {
    final raw = await connection.call((token) => _api.callValue('GET', server, '/spaces/$space/chain/$seq/seals', token: token));
    if (raw is! List<Object?>) {
      throw const KmError(KmProblem.server, message: 'a seal hash list');
    }
    try {
      return [for (final item in raw) ChainSealHash.fromJson(item)];
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// Appends [body] (`{records, seals, names, held?}`) and answers the new head. Throws a [ChainAppendError] for a 409
  /// and a 422, and a [KmError] for anything else.
  Future<ChainAppended> append(Map<String, Object?> body) => _post('/spaces/$space/chain', body);

  /// Answers pending change [id] with [body], the same as an append. The server applies the change, and a record that
  /// isn't exactly the queued change is a 422 `pending-change-mismatch`.
  Future<ChainAppended> approvePending(String id, Map<String, Object?> body) =>
      _post('/spaces/$space/chain/pending/${Uri.encodeComponent(id)}', body);

  Future<ChainAppended> _post(String route, Map<String, Object?> body) async {
    final records = body['records'];
    if (records is! List<Object?> || records.isEmpty || records.length > maxAppendRecords) {
      throw ArgumentError.value(body['records'], 'records', 'an append takes 1 to $maxAppendRecords records');
    }
    final Map<String, Object?>? answer;
    try {
      answer = await connection.call((token) => _api.call('POST', server, route, token: token, body: body));
    } on KmError catch (e) {
      if (e.status == 409) {
        throw ChainAppendError(ChainAppendFailure.headMoved, head: e.head);
      }
      if (e.status == 422) {
        throw ChainAppendError(ChainAppendFailure.refused, problem: chainProblemOf(e.reason), reason: e.reason ?? e.message, seq: e.seq);
      }
      rethrow;
    }
    final link = answer?['link'];
    final seq = answer?['seq'];
    if (link is! String || seq is! int) {
      throw const KmError(KmProblem.server, message: 'an append answers with a link and a seq');
    }
    return (link: link, seq: seq);
  }
}
