// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

pub mod argon2;
pub mod cbor;
pub mod cose;
pub mod hkdf;
pub mod rand;
pub mod rsa;
pub mod stream;
pub mod xdsa;
pub mod xhpke;

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}
