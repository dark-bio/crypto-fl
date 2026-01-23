// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Cryptographically secure random number generation.
library;

import 'dart:typed_data';

import 'src/generated/api/rand.dart' as ffi;

/// Creates an arbitrarily large buffer filled with randomness.
Uint8List bytes(int length) => ffi.randomBytes(length: BigInt.from(length));
