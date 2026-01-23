/// Cryptographically secure random number generation.
library;

import 'dart:typed_data';

import 'src/generated/api/rand.dart' as ffi;

/// Creates an arbitrarily large buffer filled with randomness.
Uint8List bytes(int length) => ffi.randomBytes(length: BigInt.from(length));
