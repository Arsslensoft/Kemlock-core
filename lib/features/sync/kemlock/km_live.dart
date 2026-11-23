/// The live socket of Kemlock Server, `/kem/v1/live` (add-kemlock-server-sync, design 13): while the app is in
/// front with the vault unlocked, the server tells the phone at once that something changed, and the phone syncs
/// without waiting for the schedule. A frame carries only its type, `sync` or `approval`, as a push nudge does.
///
/// [KmLive] keeps one socket open and opens it again when it drops, backing off from [firstDelay] and doubling to
/// [maxDelay], so a server that is down is asked a few times an hour and not every few seconds. It never opens a
/// socket by itself: the caller gives it the upgrade request (with a fresh DPoP proof) and the connector, which
/// passes the network gate. The five-minute schedule stays as the floor: a missed frame only delays a sync.
///
/// Pure Dart, no Flutter.
library;

import 'dart:async';
import 'dart:convert';

import '../../../core/network/answers.dart' show LiveSocket, LiveSocketConnector, maxLiveFrameBytes;

/// What opening the socket needs: the `wss` address, the headers of the upgrade (the DPoP proof and the token), and
/// the certificate pin of the server, if it has one.
class KmLiveUpgrade {
  const KmLiveUpgrade({required this.url, required this.headers, this.pin});

  final Uri url;
  final Map<String, String> headers;
  final String? pin;
}

/// What a frame asks for, by its type.
enum KmLiveFrame {
  /// Another device changed the vault: sync now.
  sync,

  /// Another device asks to sign in: read the requests.
  approval;

  /// The frame [text] is, or null for one this version doesn't know or can't read. A frame is a JSON object with
  /// a `type`, or the bare type.
  static KmLiveFrame? parse(String text) {
    if (text.length > maxLiveFrameBytes) {
      return null;
    }
    Object? type = text.trim();
    if (type is String && type.startsWith('{')) {
      try {
        final json = jsonDecode(type);
        type = json is Map ? json['type'] : null;
      } on FormatException {
        return null;
      }
    }
    for (final frame in values) {
      if (frame.name == type) {
        return frame;
      }
    }
    return null;
  }
}

/// Keeps the live socket open while it is started.
class KmLive {
  KmLive({required this.upgrade, required this.connect, required this.onFrame, this.clock = DateTime.now});

  /// The upgrade request for the next attempt, with a fresh proof each time; null when there is nothing to
  /// connect to now. Throwing counts as a failed attempt.
  final Future<KmLiveUpgrade?> Function() upgrade;

  /// Opens the socket, through the gate.
  final LiveSocketConnector connect;

  /// A frame of a type this version knows arrived.
  final void Function(KmLiveFrame frame) onFrame;

  final DateTime Function() clock;

  /// The first wait after a failure, and the longest.
  static const firstDelay = Duration(seconds: 2);
  static const maxDelay = Duration(minutes: 5);

  /// How long a socket must have stayed open for the next failure to start the back-off over: one that opens and
  /// is dropped at once is a server refusing, and keeps backing off.
  static const steady = Duration(seconds: 60);

  bool _running = false;
  int _round = 0;
  var _failures = 0;
  LiveSocket? _socket;
  // Cancelled in _release, on stop and when the socket drops
  // ignore: cancel_subscriptions
  StreamSubscription<String>? _frames;
  Timer? _timer;
  DateTime? _openedAt;

  /// Whether the socket is open now.
  bool get open => _socket != null;

  /// How many failures in a row there have been (0 after a socket stayed open).
  int get failures => _failures;

  /// The wait before the next attempt after [failures] failures in a row.
  static Duration delayAfter(int failures) {
    var delay = firstDelay;
    for (var i = 1; i < failures && delay < maxDelay; i++) {
      delay *= 2;
    }
    return delay > maxDelay ? maxDelay : delay;
  }

  /// Opens the socket, and again whenever it drops, until [stop].
  void start() {
    if (_running) {
      return;
    }
    _running = true;
    _failures = 0;
    unawaited(_attempt());
  }

  /// Closes the socket and stops trying. Safe to call again.
  Future<void> stop() async {
    _running = false;
    _round++;
    _timer?.cancel();
    _timer = null;
    await _release();
  }

  Future<void> _release() async {
    final frames = _frames;
    final socket = _socket;
    _frames = null;
    _socket = null;
    _openedAt = null;
    // Stop taking frames first, then close the socket at once: closing must not wait on the cancel, whose future
    // may complete only later (a plain subscription's is a shared, already completed one)
    final cancelled = frames?.cancel();
    await socket?.close();
    await cancelled;
  }

  Future<void> _attempt() async {
    if (!_running) {
      return;
    }
    final round = ++_round;
    try {
      final request = await upgrade();
      if (!_running || round != _round) {
        return;
      }
      if (request == null) {
        _fail(round);
        return;
      }
      final socket = await connect(request.url, headers: request.headers, pin: request.pin);
      if (!_running || round != _round) {
        await socket.close();
        return;
      }
      _socket = socket;
      _openedAt = clock();
      _frames = socket.frames.listen(_received, onError: (Object _) => _dropped(round), onDone: () => _dropped(round), cancelOnError: true);
    } on Object {
      _fail(round);
    }
  }

  void _received(String text) {
    final frame = KmLiveFrame.parse(text);
    if (frame != null) {
      onFrame(frame);
    }
  }

  /// The open socket ended.
  void _dropped(int round) {
    if (!_running || round != _round) {
      return;
    }
    final openedAt = _openedAt;
    final steadily = openedAt != null && clock().difference(openedAt) >= steady;
    unawaited(_release());
    if (steadily) {
      _failures = 0;
    }
    _fail(round);
  }

  /// An attempt failed or the socket dropped: try again after the back-off.
  void _fail(int round) {
    if (!_running || round != _round) {
      return;
    }
    _failures++;
    _timer?.cancel();
    _timer = Timer(delayAfter(_failures), () => unawaited(_attempt()));
  }
}
