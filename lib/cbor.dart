// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Validation of the CBOR subset that the `cose` and `cwt` libraries accept.
///
/// https://datatracker.ietf.org/doc/html/rfc8949
///
/// Encoding and decoding are left to the `cbor` package. The `cose` and `cwt`
/// libraries encode plain Dart values with it and run [verify] on the result,
/// so they only accept values that encode into this subset:
///
/// - `bool`, `null`, `int` and `String`
/// - `Uint8List` for byte strings, since any other `List<int>` encodes as an
///   array of integers
/// - Lists of supported values
/// - Maps with integer keys, built in the deterministic order of RFC 8949
///   Section 4.2.1. Non-negative keys come first in ascending order, then
///   negative keys as -1, -2, and so on
///
/// Floats, tags and indefinite lengths are rejected, so `double`, `DateTime`
/// and `Uri` values cannot be used. A `String` holding a lone surrogate is
/// rejected too, since it has no UTF-8 form.
///
/// ```dart
/// import 'dart:typed_data';
///
/// import 'package:darkbio_crypto/cbor.dart' as cbor;
///
/// void example() {
///   // [1, "two", h'03'] is within the subset
///   cbor.verify(Uint8List.fromList([0x83, 0x01, 0x63, 0x74, 0x77, 0x6f, 0x41, 0x03]));
///
///   // {2: 0, 1: 0} has its map keys out of order
///   try {
///     cbor.verify(Uint8List.fromList([0xa2, 0x02, 0x00, 0x01, 0x00]));
///   } catch (err) {
///     // Rejected, the error names the broken rule
///   }
/// }
/// ```
library;

import 'dart:typed_data';

import 'src/generated/api/cbor.dart' as ffi;

/// Checks that [data] holds exactly one complete CBOR item within the subset
/// this package accepts.
///
/// Checks UTF-8 text, deterministic integer and length encodings, integer map
/// keys in order without duplicates, and the nesting limit. It does not
/// validate application-specific schemas or values.
///
/// Throws if [data] breaks any of these rules.
void verify(Uint8List data) => ffi.cborVerify(data: data);
