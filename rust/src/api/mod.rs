// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Cryptographic FFI modules bridged to Dart.

/// Argon2id password-based key derivation.
pub mod argon2;
/// Canonical CBOR subset validation.
pub mod cbor;
/// COSE signatures and sealed envelopes.
pub mod cose;
/// CBOR Web Token issuance and verification.
pub mod cwt;
/// HKDF-SHA256 key derivation.
pub mod hkdf;
/// Operating-system random byte generation.
pub mod rand;
/// RSA-2048 signatures.
pub mod rsa;
/// STREAM authenticated encryption.
pub mod stream;
/// Composite ML-DSA-65 and Ed25519 signatures.
pub mod xdsa;
/// X-Wing hybrid public-key encryption.
pub mod xhpke;

/// Initializes default bridge utilities when the native library loads.
#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}
