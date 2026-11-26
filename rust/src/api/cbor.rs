// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Canonical CBOR subset validation for the Dart bindings.

use flutter_rust_bridge::frb;

/// Validates that `data` is one complete canonical CBOR item in the restricted
/// subset.
///
/// Checks structure, nesting depth, UTF-8 text strings, and deterministic
/// integer map key order without duplicates.
#[frb(sync)]
pub fn cbor_verify(data: Vec<u8>) -> Result<(), String> {
    darkbio_crypto::cbor::verify(&data).map_err(|e| e.to_string())
}
