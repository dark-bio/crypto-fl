// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Random bytes from the operating system's secure source.
///
/// ```dart
/// import 'package:darkbio_crypto/rand.dart' as rand;
///
/// void example() {
///   final nonce = rand.bytes(32);
///   assert(nonce.length == 32);
/// }
/// ```
library;

import 'dart:typed_data';

import 'src/generated/api/rand.dart' as ffi;

/// Creates a buffer of [length] bytes filled with randomness.
///
/// Throws if [length] is negative or above 2^32 - 1.
Uint8List bytes(int length) {
  if (length < 0 || length > 0xffffffff) {
    throw ArgumentError.value(length, 'length', 'must be 0 to 2^32 - 1');
  }
  return ffi.randomBytes(length: BigInt.from(length));
}
