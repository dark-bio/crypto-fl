// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use flutter_rust_bridge::frb;

/// Validates that the given bytes are well-formed CBOR.
///
/// This performs strict validation including:
/// - Valid CBOR structure (headers, nesting)
/// - UTF-8 validation for text strings
/// - Integer map keys in deterministic order
///
/// Returns an error if the bytes are not valid CBOR.
#[frb(sync)]
pub fn cbor_verify(data: Vec<u8>) -> Result<(), String> {
    darkbio_crypto::cbor::verify(&data).map_err(|e| e.to_string())
}
