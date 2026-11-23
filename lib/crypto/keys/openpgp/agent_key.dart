// GnuPG's own form of a secret key: the canonical S-expression gpg-agent
// keeps, which GnuPG 2.5 exports in a version 5 secret key packet under
// S2K usage 255 and the GNU extension's mode 1003, as it does for every
// Kyber key. A Kyber key is
//
//   (composite-key
//     (private-key (ecc (curve Curve25519) (flags djb-tweak) (q ...) (d ...)))
//     (private-key (kyber768 (p ...) (s ...) (seed ...))))
//
// and under a passphrase a half is a `protected-private-key` whose secret
// parameters sit in `(protected openpgp-s2k3-ocb-aes ((sha1 salt count)
// nonce) sealed)`: AES-128 in OCB with a 12-byte nonce, the key from
// Iterated and Salted S2K over SHA-1, and the rest of the list as
// associated data (gpg-agent's agent/protect.c). GnuPG 2.5.24 protects
// only the ECC half of the keys it exports and leaves the ML-KEM half in
// the clear; it reads, and Kemlock writes, both halves protected.

import 'dart:convert';
import 'dart:typed_data';

import 'modes.dart';
import 'pgp_error.dart';
import 's2k.dart';

/// One element of a canonical S-expression: an atom, or a list with the
/// offsets of its parentheses in the whole.
class Sexp {
  Sexp._atom(this.atom, this.start, this.end) : items = const [];

  Sexp._list(this.items, this.start, this.end) : atom = null;

  final Uint8List? atom;
  final List<Sexp> items;

  /// Where it starts and ends in the bytes it was read from.
  final int start;
  final int end;

  bool get isList => atom == null;

  /// The atom as text, or null for a list.
  String? get text => atom == null ? null : latin1.decode(atom!);

  /// A list's first atom as text: its name.
  String? get name => isList && items.isNotEmpty ? items.first.text : null;

  /// The first list inside named [name], at any depth; null when none is.
  Sexp? find(String name) {
    for (final item in items) {
      if (!item.isList) continue;
      if (item.name == name) return item;
      final inside = item.find(name);
      if (inside != null) return inside;
    }
    return null;
  }

  /// The value of the list `(name value)` directly inside; null when there
  /// is none.
  Uint8List? value(String name) {
    for (final item in items) {
      if (item.isList && item.name == name && item.items.length >= 2) return item.items[1].atom;
    }
    return null;
  }
}

/// Reads the canonical S-expression at the start of [data]. Throws
/// [PgpProblem.damaged] for one that is not well formed.
Sexp readSexp(Uint8List data) {
  var pos = 0;
  Sexp element(int depth) {
    pgpCheck(depth < 16 && pos < data.length, 'agent key: cut short');
    final start = pos;
    if (data[pos] == 0x28) {
      pos++;
      final items = <Sexp>[];
      while (true) {
        pgpCheck(pos < data.length, 'agent key: cut short');
        if (data[pos] == 0x29) break;
        items.add(element(depth + 1));
      }
      pos++;
      return Sexp._list(items, start, pos);
    }
    var length = 0;
    while (pos < data.length && data[pos] >= 0x30 && data[pos] <= 0x39) {
      length = length * 10 + data[pos++] - 0x30;
      pgpCheck(length <= data.length, 'agent key: atom length');
    }
    pgpCheck(pos < data.length && data[pos] == 0x3a && pos > start, 'agent key: not an atom');
    pos++;
    pgpCheck(length <= data.length - pos, 'agent key: cut short');
    final atom = Uint8List.sublistView(data, pos, pos + length);
    pos += length;
    return Sexp._atom(atom, start, pos);
  }

  return element(0);
}

/// The two secrets of a GnuPG Kyber key, as its agent key holds them.
class AgentKyberKey {
  const AgentKyberKey({required this.curve, required this.eccSecret, required this.mlKemSecret});

  /// The curve's name as the agent writes it: `Curve25519`,
  /// `brainpoolP256r1`, `brainpoolP384r1`.
  final String curve;

  /// The ECC secret `d`, as the agent keeps it.
  final Uint8List eccSecret;

  /// The expanded ML-KEM secret key `s`.
  final Uint8List mlKemSecret;
}

/// Whether some part of [key] is behind a passphrase.
bool agentKeyProtected(Sexp key) => key.find('protected') != null;

/// The secrets of the agent Kyber key [data], unlocked with [passphrase]
/// where a part is protected. Throws [PgpProblem.passphraseNeeded] when a
/// part is protected and [passphrase] is null,
/// [PgpProblem.wrongPassphrase] when it does not open it, and
/// [PgpProblem.unsupported] for a protection other than
/// `openpgp-s2k3-ocb-aes`.
AgentKyberKey readAgentKyberKey(Uint8List data, {List<int>? passphrase}) {
  final key = readSexp(data);
  pgpCheck(key.name == 'composite-key', 'agent key: not a composite key');
  final ecc = key.find('ecc');
  final kyber = key.find('kyber768') ?? key.find('kyber1024');
  pgpCheck(ecc != null && kyber != null, 'agent key: not a Kyber key');
  final curve = ecc!.value('curve');
  pgpCheck(curve != null, 'agent key: no curve');
  if (passphrase == null && agentKeyProtected(key)) throw const PgpException(PgpProblem.passphraseNeeded);
  final d = _secrets(data, ecc, passphrase).value('d');
  final mlKem = _secrets(data, kyber!, passphrase).value('s');
  pgpCheck(d != null && d.isNotEmpty && mlKem != null, 'agent key: no secret');
  return AgentKyberKey(curve: latin1.decode(curve!), eccSecret: Uint8List.fromList(d!), mlKemSecret: Uint8List.fromList(mlKem!));
}

/// The list holding the secret parameters of [list], an algorithm's list
/// in [data]: the list itself, or what its protection opens to.
Sexp _secrets(Uint8List data, Sexp list, List<int>? passphrase) {
  final protection = list.find('protected');
  if (protection == null) return list;
  return _unprotect(data, list, protection, passphrase!);
}

/// What [protection], in the list [list] of [data], opens to: the list of
/// the parameters it took out, as gpg-agent's do_decryption gives it.
Sexp _unprotect(Uint8List data, Sexp list, Sexp protection, List<int> passphrase) {
  final mode = protection.items.elementAtOrNull(1)?.text;
  if (mode != 'openpgp-s2k3-ocb-aes') throw PgpException(PgpProblem.unsupported, detail: mode ?? 'agent protection');
  final parameters = protection.items.elementAtOrNull(2);
  final sealed = protection.items.elementAtOrNull(3)?.atom;
  final s2k = parameters?.items.elementAtOrNull(0);
  final nonce = parameters?.items.elementAtOrNull(1)?.atom;
  pgpCheck(s2k != null && s2k.name == 'sha1' && s2k.items.length == 3, 'agent key: S2K');
  final salt = s2k!.items[1].atom;
  var count = int.tryParse(s2k.items[2].text ?? '') ?? 0;
  // Old agents wrote the count octet of OpenPGP
  if (count > 0 && count < 256) count = (16 + (count & 15)) << ((count >> 4) + 6);
  pgpCheck(salt != null && salt.length == 8 && count >= 65536 && count <= 1 << 31, 'agent key: S2K');
  pgpCheck(nonce != null && nonce.length == 12 && sealed != null && sealed.length >= 16, 'agent key: protection');
  final key = S2k.counted(hashSha1, salt!, count).derive(passphrase, 16);
  // The list with its (protected ...) cut out is the associated data
  final ad = Uint8List.fromList([...data.sublist(list.start, protection.start), ...data.sublist(protection.end, list.end)]);
  final plain = Ocb(key).open(nonce!, sealed!, ad);
  if (plain == null) throw const PgpException(PgpProblem.wrongPassphrase);
  // (((d ...))): the parameters it took out, in two lists
  final inner = readSexp(plain);
  pgpCheck(inner.isList && inner.items.length == 1 && inner.items.first.isList, 'agent key: protected part');
  return inner.items.first;
}

// ─── Writing ──────────────────────────────────────────────────────────────────

/// An atom of a canonical S-expression: its length, a colon, its bytes.
List<int> _atom(List<int> bytes) => [...ascii.encode('${bytes.length}:'), ...bytes];

List<int> _list(List<List<int>> items) => [0x28, for (final item in items) ...item, 0x29];

List<int> _pair(String name, List<int> value) => _list([_atom(ascii.encode(name)), _atom(value)]);

/// The agent S-expression of a Kyber-768 with X25519 key, as GnuPG 2.5
/// exports it: the ECC half with its public point [q] (0x40 and the
/// X25519 key) and its secret [d] (the X25519 secret reversed, as GnuPG's
/// packets store it), then the ML-KEM half with its public key [p], its
/// expanded secret key [s] and its [seed].
Uint8List writeAgentKyberKey({required List<int> q, required List<int> d, required List<int> p, required List<int> s, List<int>? seed}) =>
    Uint8List.fromList(
      _list([
        _atom(ascii.encode('composite-key')),
        _list([
          _atom(ascii.encode('private-key')),
          _list([
            _atom(ascii.encode('ecc')),
            _pair('curve', ascii.encode('Curve25519')),
            _pair('flags', ascii.encode('djb-tweak')),
            _pair('q', q),
            _pair('d', d),
          ]),
        ]),
        _list([
          _atom(ascii.encode('private-key')),
          _list([
            _atom(ascii.encode(p.length == 1568 ? 'kyber1024' : 'kyber768')),
            _pair('p', p),
            _pair('s', s),
            if (seed != null) _pair('seed', seed),
          ]),
        ]),
      ]),
    );

/// The plain agent Kyber key [data] with both of its halves protected by
/// [passphrase] the way gpg-agent protects a key
/// (`openpgp-s2k3-ocb-aes`): for each, 8 bytes of [random] as the salt of
/// Iterated and Salted S2K over SHA-1 with [count], 12 as the nonce of
/// AES-128 in OCB, and the time [protectedAt]. GnuPG 2.5.24 opens it
/// with that passphrase.
Uint8List protectAgentKyberKey(
  Uint8List data,
  List<int> passphrase, {
  required Uint8List Function(int length) random,
  required DateTime protectedAt,
  int count = 33554432,
}) {
  final key = readSexp(data);
  final halves = key.items.where((item) => item.isList).toList();
  pgpCheck(
    key.name == 'composite-key' && halves.length == 2 && halves.every((half) => half.name == 'private-key'),
    'agent key: not a plain Kyber key',
  );
  final t = protectedAt.toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  final stamp = _pair('protected-at', ascii.encode('${t.year}${two(t.month)}${two(t.day)}T${two(t.hour)}${two(t.minute)}${two(t.second)}'));

  List<int> protect(Sexp half, Set<String> secret) {
    final list = half.items.elementAtOrNull(1);
    pgpCheck(list != null && list.isList, 'agent key: no algorithm list');
    final parts = [
      for (final item in list!.items)
        if (item.isList && secret.contains(item.name)) item,
    ];
    pgpCheck(parts.length == secret.length || (secret.contains('seed') && parts.length == secret.length - 1), 'agent key: secret parts');
    // The secret parameters come last, together, as gpg-agent wants them
    final from = parts.first.start;
    final to = parts.last.end;
    pgpCheck(to == list.end - 1, 'agent key: secret parameters not last');
    final before = data.sublist(list.start, from);
    final after = data.sublist(to, list.end);
    final salt = random(8);
    final nonce = random(12);
    final aes = S2k.counted(hashSha1, salt, count).derive(passphrase, 16);
    // What gpg-agent authenticates: the list without its secrets, with the
    // time where the protection will be
    final sealed = Ocb(aes).seal(
      nonce,
      Uint8List.fromList([0x28, 0x28, ...data.sublist(from, to), 0x29, 0x29]),
      Uint8List.fromList([...before, ...stamp, ...after]),
    );
    final protection = _list([
      _atom(ascii.encode('protected')),
      _atom(ascii.encode('openpgp-s2k3-ocb-aes')),
      _list([
        _list([_atom(ascii.encode('sha1')), _atom(salt), _atom(ascii.encode('$count'))]),
        _atom(nonce),
      ]),
      _atom(sealed),
    ]);
    return _list([
      _atom(ascii.encode('protected-private-key')),
      [...before, ...protection, ...stamp, ...after],
    ]);
  }

  return Uint8List.fromList([
    ...data.sublist(key.start, halves.first.start),
    ...protect(halves.first, const {'d'}),
    ...data.sublist(halves.first.end, halves.last.start),
    ...protect(halves.last, const {'s', 'seed'}),
    ...data.sublist(halves.last.end, key.end),
  ]);
}
