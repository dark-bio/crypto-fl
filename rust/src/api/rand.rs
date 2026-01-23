// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use flutter_rust_bridge::frb;

/// Generates cryptographically secure random bytes.
#[frb(sync)]
pub fn random_bytes(length: usize) -> Vec<u8> {
    darkbio_crypto::rand::generate(length)
}
