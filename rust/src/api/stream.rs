// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Whole-buffer STREAM encryption and decryption for the Dart bindings.

use std::io::{Read, Write};

use darkbio_crypto::stream::{PayloadKey, Stream};
use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

/// Imports a 32-byte STREAM key and clears the bridge's input buffer.
fn payload_key(key: Vec<u8>) -> Result<PayloadKey, String> {
    let key = Zeroizing::new(key);
    let bytes = key
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid key length, expected 32 bytes".to_string())?;
    Ok(PayloadKey::from_bytes(bytes))
}

/// Encrypts plaintext with a 32-byte key unique to this stream.
#[frb(sync)]
pub fn stream_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    // Guard the plaintext before checking the key length
    let plaintext = Zeroizing::new(plaintext);
    let mut ciphertext = Vec::new();
    let mut writer = Stream::encrypt(payload_key(key)?, &mut ciphertext);

    // Finish the stream so the last chunk authenticates its end
    writer
        .write_all(&plaintext)
        .map_err(|e| format!("Encryption write error: {e}"))?;
    writer
        .finish()
        .map_err(|e| format!("Encryption finish error: {e}"))?;
    Ok(ciphertext)
}

/// Returns the plaintext once every chunk authenticates under the 32-byte key.
#[frb(sync)]
pub fn stream_decrypt(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, String> {
    // Pre-size to the ciphertext length so partial plaintext is never left behind on reallocation
    let mut reader = Stream::decrypt(payload_key(key)?, ciphertext.as_slice());
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| format!("Decryption error: {e}"))?;
    Ok(std::mem::take(&mut *plaintext))
}
