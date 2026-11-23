// Reading and writing OpenPGP data in pieces (RFC 9580 section 4.2), so a
// file is never held whole: a pull reader over a source of byte pieces, a
// packet reader that joins partial body lengths, and a packet writer that
// emits a definite length or partial pieces of 64 KiB.
//
// Everything here is synchronous: it runs in the PGP job's isolate, where
// a file is read with `RandomAccessFile`'s blocking calls (`stream_files.dart`).
// Layers stack by wrapping one [ByteSource] in another (armor, packets,
// decryption, decompression, packets again).

import 'dart:typed_data';

import 'packets.dart';
import 'pgp_error.dart';

/// The size of the pieces files are read and written in, as
/// `attachment_format.dart`'s.
const pgpPieceSize = 64 * 1024;

/// Bytes that come in pieces.
abstract interface class ByteSource {
  /// The next piece, never empty; null at the end.
  Uint8List? next();
}

/// Somewhere bytes go.
abstract interface class ByteSink {
  void add(Uint8List data);
}

/// One buffer, handed out in pieces of [pieceSize].
class BytesSource implements ByteSource {
  BytesSource(this._bytes, {this.pieceSize = pgpPieceSize});

  final Uint8List _bytes;
  final int pieceSize;
  int _pos = 0;

  @override
  Uint8List? next() {
    if (_pos >= _bytes.length) return null;
    final end = _pos + pieceSize > _bytes.length ? _bytes.length : _pos + pieceSize;
    final piece = Uint8List.sublistView(_bytes, _pos, end);
    _pos = end;
    return piece;
  }
}

/// Collects what it is given in memory.
class BytesSink implements ByteSink {
  final _builder = BytesBuilder(copy: true);

  @override
  void add(Uint8List data) => _builder.add(data);

  int get length => _builder.length;

  Uint8List takeBytes() => _builder.takeBytes();
}

/// Reads a [ByteSource] by counts: "the next n bytes" and "the rest, in
/// pieces". It is a [ByteSource] itself.
class PgpReader implements ByteSource {
  PgpReader(this._source);

  PgpReader.bytes(Uint8List bytes) : _source = BytesSource(bytes);

  final ByteSource _source;
  Uint8List _piece = Uint8List(0);
  int _pos = 0;
  bool _ended = false;

  bool _fill() {
    while (_pos >= _piece.length) {
      if (_ended) return false;
      final next = _source.next();
      if (next == null) {
        _ended = true;
        return false;
      }
      _piece = next;
      _pos = 0;
    }
    return true;
  }

  /// Whether nothing is left.
  bool get atEnd => !_fill();

  /// The next byte without taking it; null at the end.
  int? peek() => _fill() ? _piece[_pos] : null;

  /// The next byte. Throws [PgpProblem.damaged] at the end.
  int byte() {
    pgpCheck(_fill(), 'cut short');
    return _piece[_pos++];
  }

  int uint16() => (byte() << 8) | byte();

  int uint32() => (uint16() << 16) | uint16();

  /// Exactly [n] bytes. Throws [PgpProblem.damaged] when fewer are left.
  ///
  /// The count is often a length the data itself gives, up to four
  /// gigabytes of it, so nothing is set aside for it ahead: the bytes are
  /// gathered as the source hands them over, and a count past the end costs
  /// no more than what was there.
  Uint8List bytes(int n) {
    pgpCheck(n >= 0, 'length');
    if (n == 0) return Uint8List(0);
    pgpCheck(_fill(), 'cut short');
    if (_piece.length - _pos >= n) {
      final out = Uint8List.sublistView(_piece, _pos, _pos + n);
      _pos += n;
      return out;
    }
    final out = BytesBuilder(copy: true);
    while (out.length < n) {
      pgpCheck(_fill(), 'cut short');
      final left = n - out.length;
      final take = _piece.length - _pos < left ? _piece.length - _pos : left;
      out.add(Uint8List.sublistView(_piece, _pos, _pos + take));
      _pos += take;
    }
    return out.takeBytes();
  }

  /// Up to [max] bytes of what is at hand; null at the end.
  Uint8List? some([int max = pgpPieceSize]) {
    if (!_fill()) return null;
    final take = _piece.length - _pos < max ? _piece.length - _pos : max;
    final out = Uint8List.sublistView(_piece, _pos, _pos + take);
    _pos += take;
    return out;
  }

  @override
  Uint8List? next() => some();

  /// Everything that is left, in one buffer. Throws [PgpProblem.tooLarge]
  /// past [max] bytes.
  Uint8List rest({required int max}) {
    final out = BytesBuilder(copy: true);
    for (var piece = some(); piece != null; piece = some()) {
      if (out.length + piece.length > max) throw const PgpException(PgpProblem.tooLarge);
      out.add(piece);
    }
    return out.takeBytes();
  }

  /// Reads to the end and throws what was read away.
  void drain() {
    while (some() != null) {}
  }
}

/// A packet being read: its [tag] and its [body], which must be read to
/// its end (or [PacketReader.next] does it) before the next packet.
class PacketIn {
  PacketIn(this.tag, this.body, {required this.partial});

  final int tag;
  final PgpReader body;

  /// Whether the body came in partial lengths or to the end of the data.
  final bool partial;
}

/// The packets of a stream, one after the other, in either header format.
/// A body in partial lengths is joined; an old-format packet of
/// indeterminate length runs to the end.
class PacketReader {
  PacketReader(this._in);

  final PgpReader _in;
  PacketIn? _current;

  /// Tags whose body may come in partial lengths (RFC 9580 section
  /// 4.2.1.4): literal, compressed and encrypted data.
  static const _dataTags = {PgpTag.literalData, PgpTag.compressedData, PgpTag.encryptedData, PgpTag.seipd, PgpTag.ocbEncryptedData};

  /// The next packet; null at the end. Throws [PgpProblem.damaged] for a
  /// header that isn't one.
  PacketIn? next() {
    _current?.body.drain();
    _current = null;
    if (_in.atEnd) return null;
    final ctb = _in.byte();
    pgpCheck(ctb & 0x80 != 0, 'not a packet header');
    final int tag;
    final ByteSource body;
    var partial = false;
    if (ctb & 0x40 == 0) {
      tag = (ctb >> 2) & 0x0f;
      switch (ctb & 3) {
        case 0:
          body = _Counted(_in, _in.byte());
        case 1:
          body = _Counted(_in, _in.uint16());
        case 2:
          body = _Counted(_in, _in.uint32());
        default:
          pgpCheck(_dataTags.contains(tag), 'indeterminate length');
          partial = true;
          body = _in;
      }
    } else {
      tag = ctb & 0x3f;
      final first = _in.byte();
      if (first < 192) {
        body = _Counted(_in, first);
      } else if (first < 224) {
        body = _Counted(_in, ((first - 192) << 8) + _in.byte() + 192);
      } else if (first == 255) {
        body = _Counted(_in, _in.uint32());
      } else {
        pgpCheck(_dataTags.contains(tag), 'partial length');
        // The first partial piece is at least 512 bytes
        pgpCheck(first >= 224 + 9, 'short first partial length');
        partial = true;
        body = _Partial(_in, 1 << (first & 0x1f));
      }
    }
    pgpCheck(tag != 0, 'packet tag 0');
    return _current = PacketIn(tag, PgpReader(body), partial: partial);
  }
}

/// [_left] bytes of a reader, and an error if it ends before them.
class _Counted implements ByteSource {
  _Counted(this._in, this._left);

  final PgpReader _in;
  int _left;

  @override
  Uint8List? next() {
    if (_left == 0) return null;
    final piece = _in.some(_left);
    if (piece == null) throw const PgpException(PgpProblem.damaged, detail: 'length past the end');
    _left -= piece.length;
    return piece;
  }
}

/// A body in partial lengths: pieces of a power of two, then a last one
/// with an ordinary length.
class _Partial implements ByteSource {
  _Partial(this._in, this._left);

  final PgpReader _in;
  int _left;
  bool _last = false;

  @override
  Uint8List? next() {
    while (_left == 0) {
      if (_last) return null;
      final first = _in.byte();
      if (first < 192) {
        _left = first;
        _last = true;
      } else if (first < 224) {
        _left = ((first - 192) << 8) + _in.byte() + 192;
        _last = true;
      } else if (first == 255) {
        _left = _in.uint32();
        _last = true;
      } else {
        _left = 1 << (first & 0x1f);
      }
    }
    final piece = _in.some(_left);
    if (piece == null) throw const PgpException(PgpProblem.damaged, detail: 'length past the end');
    _left -= piece.length;
    return piece;
  }
}

/// The new-format header of a packet with [tag] and a body of [length].
Uint8List packetHeader(int tag, int length) => Uint8List.fromList([0xc0 | tag, ..._definiteLength(length)]);

List<int> _definiteLength(int length) => length < 192
    ? [length]
    : length < 8384
    ? [((length - 192) >> 8) + 192, (length - 192) & 0xff]
    : [0xff, (length >>> 24) & 0xff, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff];

/// Writes one new-format packet into [_out] as its body arrives: with a
/// definite length when [length] is given, else in partial pieces of
/// 64 KiB and a last piece of what is left. [close] ends it.
class PacketWriter implements ByteSink {
  PacketWriter(this._out, int tag, {int? length}) : _length = length {
    if (length != null) {
      _out.add(packetHeader(tag, length));
    } else {
      _out.add(Uint8List.fromList([0xc0 | tag]));
    }
  }

  final ByteSink _out;
  final int? _length;
  final _held = Uint8List(pgpPieceSize);
  int _fill = 0;
  int _written = 0;

  @override
  void add(Uint8List data) {
    _written += data.length;
    if (_length != null) {
      _out.add(data);
      return;
    }
    var pos = 0;
    while (pos < data.length) {
      // A full piece goes out only once more is known to follow, so the
      // last piece is never empty unless the body is
      if (_fill == pgpPieceSize) _flushPartial();
      final take = data.length - pos < pgpPieceSize - _fill ? data.length - pos : pgpPieceSize - _fill;
      _held.setRange(_fill, _fill + take, data, pos);
      _fill += take;
      pos += take;
    }
  }

  void _flushPartial() {
    // 0xf0: a partial piece of 2^16 bytes
    _out
      ..add(Uint8List.fromList([0xf0]))
      ..add(Uint8List.fromList(_held));
    _fill = 0;
  }

  void close() {
    if (_length != null) {
      if (_written != _length) throw StateError('a packet of $_length bytes was given $_written');
      return;
    }
    _out
      ..add(Uint8List.fromList(_definiteLength(_fill)))
      ..add(Uint8List.fromList(Uint8List.sublistView(_held, 0, _fill)));
    _fill = 0;
  }
}
