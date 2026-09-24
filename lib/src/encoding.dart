// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:cbor/cbor.dart';

/// Encodes a plain Dart value with the `cbor` package, giving every list and
/// map a definite length. The package would otherwise encode collections of
/// 256 or more entries with an indefinite length.
Uint8List encode(Object? value) =>
    Uint8List.fromList(cborEncode(_convert(value)));

/// Converts a plain Dart value into its CBOR form, recursing into lists and
/// maps to fix their lengths. Values that are already CBOR pass through
/// unchanged, tags included.
CborValue _convert(Object? value) => switch (value) {
  CborValue() => value,
  String() when !_isWellFormed(value) => throw ArgumentError.value(
    value,
    'value',
    'holds a lone surrogate, which has no UTF-8 form',
  ),
  Uint8List() => CborBytes(value),
  List() => CborList([
    for (final item in value) _convert(item),
  ], type: CborLengthType.definite),
  Map() => CborMap({
    for (final entry in value.entries)
      _convert(entry.key): _convert(entry.value),
  }, type: CborLengthType.definite),
  _ => CborValue(value),
};

/// Reports whether [text] is well-formed UTF-16. The `cbor` package would
/// silently encode a lone surrogate as U+FFFD, signing a different string.
bool _isWellFormed(String text) {
  for (var i = 0; i < text.length; i++) {
    final unit = text.codeUnitAt(i);
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (i + 1 == text.length) {
        return false;
      }
      final next = text.codeUnitAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        return false;
      }
      i++;
    }
  }
  return true;
}
