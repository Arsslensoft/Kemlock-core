/// The pure part of the network code: how an answer is read with a limit, and what a live socket is to the code that
/// listens on it. `platform/network.dart` re-exports it and adds what needs `dart:io` and Riverpod.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

/// What [readAnswer] throws for an answer longer than it takes. It is an
/// [http.ClientException], so code that already handles a failed request
/// handles it.
class AnswerTooLarge extends http.ClientException {
  AnswerTooLarge([Uri? uri]) : super('The answer is larger than it may be.', uri);
}

/// [response] read whole, as `http.Response.fromStream` reads it, but never
/// past [maxBytes]: a server's answer is read into memory, and one that
/// never ends would fill it. An answer whose `Content-Length` is over the
/// limit is refused before any of it is read, and one that runs past it is
/// dropped there and its connection closed; both throw [AnswerTooLarge].
Future<http.Response> readAnswer(http.StreamedResponse response, int maxBytes) async {
  final url = response.request?.url;
  if ((response.contentLength ?? 0) > maxBytes) {
    // Listening and leaving at once closes the connection
    unawaited(response.stream.listen(null, onError: (Object _) {}).cancel());
    throw AnswerTooLarge(url);
  }
  final body = BytesBuilder(copy: false);
  await for (final chunk in response.stream) {
    if (body.length + chunk.length > maxBytes) throw AnswerTooLarge(url);
    body.add(chunk);
  }
  return http.Response.bytes(
    body.takeBytes(),
    response.statusCode,
    request: response.request,
    headers: response.headers,
    isRedirect: response.isRedirect,
    persistentConnection: response.persistentConnection,
    reasonPhrase: response.reasonPhrase,
  );
}

/// What a live socket is to the code that listens on it: the frames it receives, and the end of it. The socket
/// of [connectLiveSocket] is one; tests make their own.
abstract interface class LiveSocket {
  /// The text frames the server sends, ending when the socket closes. An error ends it too.
  Stream<String> get frames;

  /// Closes the socket. Closing a closed socket does nothing.
  Future<void> close();
}

/// Opens a [LiveSocket] to [url], carrying [headers] on the upgrade request: the Kemlock Server's `/kem/v1/live`,
/// whose upgrade carries DPoP (add-kemlock-server-sync, design 13). Whoever calls this passes the gate first, as
/// [connectLiveSocket] does.
typedef LiveSocketConnector = Future<LiveSocket> Function(Uri url, {Map<String, String> headers, String? pin});

/// The ping that finds a dead connection: a socket whose far end vanished would otherwise stay open for ever.
const liveSocketPing = Duration(seconds: 30);

/// The longest text frame taken; a nudge carries its type and nothing else.
const maxLiveFrameBytes = 4096;
