// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! HKDF-SHA256 key derivation for the Dart bindings.

use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

/// Derives `length` bytes from a secret, salt and context using HKDF-SHA256.
///
/// # Panics
///
/// Panics if `length` exceeds 8160 bytes.
#[frb(sync)]
pub fn hkdf_key(secret: Vec<u8>, salt: Vec<u8>, info: Vec<u8>, length: usize) -> Vec<u8> {
    darkbio_crypto::hkdf::key_with_len(&Zeroizing::new(secret), &salt, &info, length).to_vec()
}

/// Extracts a 32-byte pseudorandom key for subsequent expansion calls.
#[frb(sync)]
pub fn hkdf_extract(secret: Vec<u8>, salt: Vec<u8>) -> Vec<u8> {
    darkbio_crypto::hkdf::extract(&Zeroizing::new(secret), &salt).to_vec()
}

/// Expands a 32-byte pseudorandom key into `length` context-bound bytes.
///
/// # Panics
///
/// Panics if `length` exceeds 8160 bytes and the key has the required length.
#[frb(sync)]
pub fn hkdf_expand(prk: Vec<u8>, info: Vec<u8>, length: usize) -> Result<Vec<u8>, String> {
    let prk = Zeroizing::new(prk);
    let key = prk
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid PRK length, expected 32 bytes".to_string())?;

    Ok(darkbio_crypto::hkdf::expand_with_len(key, &info, length).to_vec())
}
