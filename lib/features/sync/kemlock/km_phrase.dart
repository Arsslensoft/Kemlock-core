/// The device-approval phrase: five words a new device and the device that
/// approves it both show, so a person can see that the key about to receive
/// the account's root key is the one the new device made. It is `crypto.md`'s
/// "Device-approval phrase":
///
///     digest = SHA-256("kemlock approval v1" || the new device's one-time kx1 public key (1600))
///     bits   = the first 65 bits of digest, most significant first
///     word i = list[(bits[13i .. 13i+13] as a big-endian number) mod 7776],  i = 0 .. 4
///
/// over EFF's large word list. Each device computes the phrase itself, from
/// the public key it made (the new device) or the key it is about to seal to
/// (the approving device). The phrase the server sends along is only a
/// cross-check ([phrasesAgree]) and is never shown, or a server could swap a
/// key and send matching words to both screens.
///
/// This replaces the 12 groups of 5 digits the plan first had for approvals
/// (design 11): the server fixed five words.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/kx1.dart';

/// How many words EFF's large list has.
const effWordCount = 7776;

/// How many words a phrase has.
const approvalPhraseWords = 5;

const _label = 'kemlock approval v1';

/// The five words of [publicKey] (the one-time `kx1` public key, 1,600 bytes), lower case, joined by single
/// spaces. [words] is EFF's large list in its order, 7,776 words, as `wordListProvider` reads it from the
/// bundled file (its second column; the first holds the dice digits). A key or a list of another size is a
/// [MalformedException].
String approvalPhrase(List<int> publicKey, List<String> words) {
  requireLength(publicKey, Kx1.publicKeyLength, 'a kx1 public key');
  if (words.length != effWordCount) throw MalformedException('the word list has $effWordCount words, not ${words.length}');
  final digest = hash.sha256.convert([...utf8.encode(_label), ...publicKey]).bytes;
  return [for (var i = 0; i < approvalPhraseWords; i++) words[_bits(digest, 13 * i, 13) % effWordCount]].join(' ');
}

/// [count] bits of [bytes] from bit [start], most significant first, as a number.
int _bits(List<int> bytes, int start, int count) {
  var value = 0;
  for (var bit = start; bit < start + count; bit++) {
    value = (value << 1) | ((bytes[bit >> 3] >> (7 - (bit & 7))) & 1);
  }
  return value;
}

/// Whether the phrase the server sent is the one this device computed, ignoring case and spacing. A phrase
/// that differs stops the approval: the server holds another key than the one the words were made from.
bool phrasesAgree(String computed, String fromServer) => _normal(computed) == _normal(fromServer);

String _normal(String phrase) => phrase.trim().toLowerCase().split(RegExp(r'\s+')).join(' ');

/// The words of a phrase, in order, for the sheets to show one by one.
List<String> phraseWords(String phrase) => _normal(phrase).split(' ');
