// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Password-based key derivation for the Dart bindings.

use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

/// Derives `key_length` bytes with Argon2id and clears the native password
/// buffer after use.
///
/// `time` counts passes, `memory` is in KiB, and `threads` counts lanes.
///
/// # Panics
///
/// Panics if the parameters exceed Argon2id's limits or allocation fails.
#[frb(sync)]
pub fn argon2_key(
    password: Vec<u8>,
    salt: Vec<u8>,
    time: u32,
    memory: u32,
    threads: u32,
    key_length: usize,
) -> Vec<u8> {
    let password = Zeroizing::new(password);
    darkbio_crypto::argon2::key_with_len(&password, &salt, time, memory, threads, key_length)
        .to_vec()
}
