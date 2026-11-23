/// Device approvals, both sides (add-kemlock-server-sync, design 11).
///
/// **An open phone approves** ([KmApprovals]). It reads
/// `GET /devices/approvals` while the vault is open (on open, on a nudge, at
/// each sync), drops requests older than 15 minutes, and shows the rest with
/// the five-word phrase it computes itself from the request's one-time `kx1`
/// public key ([approvalPhrase]). The server's own words are a cross-check
/// only: if they differ from the computed ones the server holds another key
/// than the one the words were made from, and the approval stops. Approve
/// asks the owner (`ownerCheckProvider`, always, whatever "Ask before showing
/// a secret" says), seals the root key to the request's key in a sealed box
/// under the `"device-approval"` context, and posts only that blob. Deny
/// posts a refusal and no key.
///
/// **A new phone waits for approval** ([KmApprovalFlow]), after SSO or when it
/// has no other way to open the account. It makes a one-time `kx1` key pair,
/// asks, shows its own phrase, polls the request every 2 seconds for up to 15
/// minutes, and opens the answer with its private key. Then it signs in by the
/// device key: a challenge for the approved request, answered with a proof of
/// the same key that made the request.
///
/// Pure Dart, no Flutter. Time comes in as functions so a fake clock runs a
/// 15-minute wait in no time.
library;

import 'dart:async';
import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/keys.dart';
import '../../../crypto/account/kx1.dart';
import '../../../crypto/account/sealed_box.dart';
import 'km_account.dart';
import 'km_api.dart';
import 'km_auth_api.dart';
import 'km_phrase.dart';
import 'km_signin.dart';

/// How long a request lives, and how long the new phone waits for an answer.
const approvalLifetime = Duration(minutes: 15);

/// How often the new phone asks whether its request was answered.
const approvalPollInterval = Duration(seconds: 2);

/// Why an approval stopped. The names are the ends of the `kemlock.approval.problem.*` message ids.
enum KmApprovalIssue {
  /// The owner didn't show it is them: nothing was sealed or sent.
  ownerCheck,

  /// The server's five words aren't the ones this phone computed from the key: the server holds another key
  /// than the one the words were made from. Nothing was sent.
  phraseMismatch,

  /// The server's list gave no public key for the request, so there is nothing to seal to or to compute the
  /// words from: this server can't be approved from here yet.
  noKey,

  /// The request is older than 15 minutes, or the server says it expired.
  expired,
}

/// An approval that stopped.
class KmApprovalError implements Exception {
  const KmApprovalError(this.issue);

  final KmApprovalIssue issue;

  @override
  String toString() => 'KmApprovalError(${issue.name})';
}

/// A pending request as the open phone shows it.
class KmPendingApproval {
  const KmPendingApproval({required this.request, required this.phrase, required this.age, required this.serverPhraseAgrees});

  final KmApprovalRequest request;

  /// The five words this phone computed from the request's key, or null when the server gave no key.
  /// These are the words shown; never the server's.
  final String? phrase;
  final Duration age;

  /// Whether the server's words are the computed ones. When false the sheet says to deny, and Approve stops.
  final bool serverPhraseAgrees;

  bool get canApprove => phrase != null && serverPhraseAgrees;
}

/// Asks the owner to show it is them; true when they did. The host gives `ownerCheckProvider`'s.
typedef KmOwnerCheck = Future<bool> Function(String reason);

/// The extra binding of the device-approval sealed box: the account id (16 bytes) then the approval request's id
/// (16), so an answer can't be replayed onto another request (`docs/crypto.md`, the sealed box's contexts).
Uint8List approvalAad(String accountId, String requestId) => Uint8List.fromList([...uuidBytes(accountId), ...uuidBytes(requestId)]);

/// The open phone's side.
class KmApprovals {
  KmApprovals({
    required this.auth,
    required this.connection,
    required this.words,
    required this.account,
    required this.ownerCheck,
    this.clock = DateTime.now,
  });

  final KmAuthApi auth;
  final KmConnection connection;

  /// EFF's large list, as `wordListProvider` reads it.
  final List<String> words;

  /// The account whose root key is sealed. Not wiped here.
  final KmAccount account;
  final KmOwnerCheck ownerCheck;
  final DateTime Function() clock;

  Uri get _server => connection.server;

  /// The requests to show: open ones under 15 minutes old, newest first, each with the phrase computed here.
  Future<List<KmPendingApproval>> pending() async {
    final requests = await connection.call((token) => auth.approvals(_server, token));
    final now = clock();
    final shown = <KmPendingApproval>[];
    for (final request in requests) {
      final age = now.difference(request.createdAt);
      if (age > approvalLifetime || !request.expiresAt.isAfter(now)) continue;
      final key = request.publicKey;
      final phrase = key == null || key.length != Kx1.publicKeyLength ? null : approvalPhrase(key, words);
      shown.add(
        KmPendingApproval(
          request: request,
          phrase: phrase,
          age: age < Duration.zero ? Duration.zero : age,
          serverPhraseAgrees: phrase != null && phrasesAgree(phrase, request.phrase),
        ),
      );
    }
    shown.sort((a, b) => a.age.compareTo(b.age));
    return shown;
  }

  /// Approves [pending]: asks the owner, seals the root key to the request's key and posts the blob. Throws a
  /// [KmApprovalError] before anything is sealed when the owner doesn't show it, the key is missing, the
  /// words differ or the request is too old.
  Future<void> approve(KmPendingApproval pending, {required String reason}) async {
    final key = pending.request.publicKey;
    if (key == null || pending.phrase == null) throw const KmApprovalError(KmApprovalIssue.noKey);
    if (!pending.serverPhraseAgrees) throw const KmApprovalError(KmApprovalIssue.phraseMismatch);
    if (clock().difference(pending.request.createdAt) > approvalLifetime || !pending.request.expiresAt.isAfter(clock())) {
      throw const KmApprovalError(KmApprovalIssue.expired);
    }
    if (!await ownerCheck(reason)) throw const KmApprovalError(KmApprovalIssue.ownerCheck);
    final sealed = await sealBox(
      key,
      account.rootKey,
      context: SealContext.deviceApproval,
      aad: approvalAad(account.accountId, pending.request.id),
    );
    await connection.call((token) => auth.answerApproval(_server, token, pending.request.id, sealedKey: sealed));
  }

  /// Denies [pending]: posts a refusal that carries no key.
  Future<void> deny(KmPendingApproval pending) => connection.call((token) => auth.answerApproval(_server, token, pending.request.id));
}

/// How a new phone's wait for approval ended.
sealed class KmApprovalOutcome {
  const KmApprovalOutcome();
}

/// Approved: the phone is signed in and the account is open.
class KmApproved extends KmApprovalOutcome {
  const KmApproved(this.signedIn);

  final KmSignedIn signedIn;
}

/// An open device denied the request.
class KmApprovalDenied extends KmApprovalOutcome {
  const KmApprovalDenied();
}

/// Nobody answered in 15 minutes, or the server says the request expired or was used: the other ways in are offered.
class KmApprovalTimedOut extends KmApprovalOutcome {
  const KmApprovalTimedOut();
}

/// A new phone's side: one request, from asking to the opened account.
class KmApprovalFlow {
  KmApprovalFlow(
    this.signIn, {
    required this.words,
    this.clock = DateTime.now,
    this.delay = _sleep,
    this.interval = approvalPollInterval,
    this.timeout = approvalLifetime,
    this.accountId,
  });

  final KmSignIn signIn;

  /// The account the request is for, when this phone already knows it (after SSO, from its session). The box is
  /// bound to it, so a phone that doesn't know it takes it from the server's answer (`accountId`).
  final String? accountId;
  final List<String> words;
  final DateTime Function() clock;

  /// Waits between polls; a test's advances its fake clock instead.
  final Future<void> Function(Duration) delay;
  final Duration interval;
  final Duration timeout;

  static Future<void> _sleep(Duration duration) => Future<void>.delayed(duration);

  KmApprovalTicket? _ticket;
  Uint8List? _privateKey;
  String? _phrase;
  var _cancelled = false;

  /// The five words this phone computed from its own one-time key, once [start] ran. Never the server's.
  String? get phrase => _phrase;

  /// The request's id, once [start] ran.
  String? get requestId => _ticket?.id;

  /// Makes the one-time key pair and asks the account's open devices to approve this one. Returns the phrase to
  /// show. A server whose words differ from the computed ones stops the request before anyone is asked to approve.
  Future<String> start(String email) async {
    final pair = await Kx1.generate();
    _privateKey = pair.privateKey;
    final phrase = approvalPhrase(pair.publicKey, words);
    final ticket = await signIn.auth.approvalRequest(signIn.server, email, pair.publicKey, signIn.device);
    if (!phrasesAgree(phrase, ticket.phrase)) {
      close();
      throw const KmApprovalError(KmApprovalIssue.phraseMismatch);
    }
    _ticket = ticket;
    _phrase = phrase;
    return phrase;
  }

  /// The person gives up waiting: [wait] ends at its next turn.
  void cancel() => _cancelled = true;

  /// Polls every [interval] until the request is answered or [timeout] passes. An answer opens the account:
  /// the sealed root key opens with the one-time private key, the device key signs in through the server's
  /// challenge, and the account opens from the root key.
  Future<KmApprovalOutcome> wait() async {
    final ticket = _ticket;
    if (ticket == null) throw StateError('start the request first');
    final deadline = clock().add(timeout);
    try {
      while (!_cancelled && clock().isBefore(deadline)) {
        final KmApprovalPoll poll;
        try {
          poll = await signIn.auth.approvalPoll(signIn.server, ticket.id);
        } on KmError catch (e) {
          // A hiccup in the connection doesn't end a wait that has minutes left
          if (e.problem != KmProblem.network) rethrow;
          await delay(interval);
          continue;
        }
        switch (poll.status) {
          case 'approved':
            final sealed = poll.sealedKey;
            if (sealed == null) throw const KmSignInError(KmSignInIssue.unreadable, detail: 'approved with no key');
            return KmApproved(await _open(ticket, sealed, poll.accountId ?? accountId));
          case 'denied':
            return const KmApprovalDenied();
          case 'expired' || 'used':
            return const KmApprovalTimedOut();
        }
        await delay(interval);
      }
      return const KmApprovalTimedOut();
    } finally {
      close();
    }
  }

  Future<KmSignedIn> _open(KmApprovalTicket ticket, Uint8List sealed, String? account) async {
    final privateKey = _privateKey!;
    if (account == null || !isUuidText(account)) {
      throw const KmSignInError(KmSignInIssue.unreadable, detail: 'the approval is bound to an account this phone doesn’t know');
    }
    final Uint8List root;
    try {
      root = await openBox(sealed, privateKey, context: SealContext.deviceApproval, aad: approvalAad(account, ticket.id));
    } on MalformedException catch (e) {
      throw KmSignInError(KmSignInIssue.unreadable, detail: e.message);
    } on CorruptedException {
      throw const KmSignInError(KmSignInIssue.unreadable, detail: 'the approval doesn’t open with this phone’s key');
    }
    try {
      if (root.length != rootKeyLength) throw const KmSignInError(KmSignInIssue.unreadable, detail: 'the approved key is the wrong size');
      // The device key signs in: a challenge for the approved request, sent back with a proof of the key that asked
      final challenge = await signIn.auth.deviceChallenge(signIn.server, ticket.id);
      final grant = await signIn.auth.deviceVerify(signIn.server, challenge);
      final step = await signIn.continueWith(KmSignInAnswer(grant: grant));
      final signed = step as KmSignedIn;
      final account = await signIn.openWithRoot(signed.session, root);
      return KmSignedIn(session: signed.session, account: account);
    } finally {
      wipe(root);
    }
  }

  /// Wipes the one-time private key.
  void close() {
    final key = _privateKey;
    if (key != null) wipe(key);
    _privateKey = null;
  }
}
