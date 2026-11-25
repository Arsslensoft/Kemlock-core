/// Sends links, from `docs/crypto.md` "Sends": `https://<host>/#/send/<access id>/<base64url(K)>`. The access id is
/// the send id's 16 bytes in base64url, 22 characters, and the key is the 32-byte link key, 43 characters. The key
/// is only ever in the fragment, which a browser never sends: it goes into no request, header or log, and
/// [SendLink.toString] hides it.
///
/// A Bitwarden Send link has the same shape with a 16-byte key, 22 characters. Kemlock opens none: it hands the
/// link to the browser ([BitwardenSendLink]).
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../crypto/account/encoding.dart';
import '../../crypto/account/send.dart';
import '../sync/kemlock/km_api.dart';

/// The link of the Send [sendId] with key [linkKey] on [server], the address the account signed in to, path
/// included.
String sendLink(Uri server, List<int> sendId, List<int> linkKey) {
  requireLength(linkKey, sendLinkKeyLength, 'the link key');
  return '$server/#/send/${sendAccessId(sendId)}/${b64urlEncode(linkKey)}';
}

/// A link [SendLink.parse] read: a Kemlock Send, or a Bitwarden one.
sealed class ReceivedSendLink {
  const ReceivedSendLink();
}

/// A Kemlock Send link: where to ask ([server], with its path), which Send, and the key that opens it.
final class SendLink extends ReceivedSendLink {
  SendLink({required this.server, required List<int> sendId, required List<int> key})
    : sendId = Uint8List.fromList(requireLength(sendId, 16, 'a send id')),
      key = Uint8List.fromList(requireLength(key, sendLinkKeyLength, 'the link key'));

  /// Reads the first Send link in [text], which may be a whole URL or a longer text, such as a message pasted whole.
  /// Anything that isn't one gives null: an `http` address, a user-info part, a query, padded or standard-alphabet
  /// base64, an access id that isn't 22 characters of 16 bytes, or a key that is neither 32 bytes (a Kemlock Send)
  /// nor 16 (a Bitwarden one, [BitwardenSendLink]).
  static ReceivedSendLink? parse(String text) {
    for (final word in text.split(_space)) {
      final link = _parseWord(word);
      if (link != null) return link;
    }
    return null;
  }

  /// The server's address, `https`, with its path and no trailing slash.
  final Uri server;

  /// The send id, 16 bytes.
  final Uint8List sendId;

  /// The link key `K`, 32 bytes. Wiped by [wipeKey].
  final Uint8List key;

  /// The access id, 22 characters.
  String get accessId => sendAccessId(sendId);

  /// The host, with the port when it isn't https's own, for status lines.
  String get host => kmHost(server.toString());

  /// Zeroes the key. The link can't open a Send afterwards.
  void wipeKey() => wipe(key);

  /// The link as text, as a Copy writes it: with the key. Never for a log.
  String toLinkText() => sendLink(server, sendId, key);

  @override
  String toString() => 'SendLink($host, $accessId, key hidden)';
}

/// A Bitwarden Send link, whose 16-byte key marks a Send of Bitwarden's own format. [url] is the link as it was
/// found, for the browser; nothing else reads it.
final class BitwardenSendLink extends ReceivedSendLink {
  const BitwardenSendLink(this.url, this.host);

  final String url;
  final String host;

  @override
  String toString() => 'BitwardenSendLink($host, key hidden)';
}

final _space = RegExp(r'\s+');
final _fragment = RegExp(r'^/send/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)$');

// What a message puts around a link: a bracket, a quote, a full stop.
const _before = '<([{"\'';
const _after = '>)]}"\'.,;:!?';

ReceivedSendLink? _parseWord(String word) {
  var start = 0;
  var end = word.length;
  while (start < end && _before.contains(word[start])) {
    start++;
  }
  while (end > start && _after.contains(word[end - 1])) {
    end--;
  }
  final url = word.substring(start, end);
  if (url.length < 8 || url.substring(0, 8).toLowerCase() != 'https://') return null;
  final hash = url.indexOf('#');
  if (hash < 0) return null;
  final match = _fragment.firstMatch(url.substring(hash + 1));
  if (match == null) return null;
  final Uri server;
  try {
    server = kmServerUrl(url.substring(0, hash));
  } on KmError {
    return null;
  }
  final Uint8List sendId;
  final Uint8List key;
  try {
    sendId = sendIdFromAccessId(match.group(1)!);
    key = b64urlDecode(match.group(2)!);
  } on MalformedException {
    return null;
  }
  final length = key.length;
  if (length == sendLinkKeyLength) {
    final link = SendLink(server: server, sendId: sendId, key: key);
    wipe(key);
    return link;
  }
  wipe(key);
  if (length == 16) {
    return BitwardenSendLink(url, kmHost(server.toString()));
  }
  return null;
}
