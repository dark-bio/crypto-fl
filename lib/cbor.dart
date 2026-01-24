// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// CBOR validation utilities.
///
/// This library provides strict validation for CBOR-encoded data to ensure
/// it conforms to the subset of CBOR used by this package.
library;

import 'dart:typed_data';

import 'src/generated/api/cbor.dart' as ffi;

/// Validates that the given bytes are well-formed CBOR.
///
/// This performs strict validation including:
/// - Valid CBOR structure (headers, nesting)
/// - UTF-8 validation for text strings
/// - Integer map keys in deterministic order
///
/// Throws an exception if the bytes are not valid CBOR.
void verify(Uint8List data) => ffi.cborVerify(data: data);
