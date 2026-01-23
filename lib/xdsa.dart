// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Composite ML-DSA cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
library;

import 'src/generated/api/xdsa.dart' as ffi;

/// An ML-DSA-65 private key paired with an Ed25519 private key for creating
/// and verifying quantum resistant digital signatures.
typedef SecretKey = ffi.XdsaSecretKey;

/// An ML-DSA-65 public key paired with an Ed25519 public key for verifying
/// quantum resistant digital signatures.
typedef PublicKey = ffi.XdsaPublicKey;

/// A composite ML-DSA-65 + Ed25519 digital signature (3373 bytes).
typedef Signature = ffi.XdsaSignature;

/// A 32-byte unique identifier for an xDSA key.
typedef Fingerprint = ffi.XdsaFingerprint;
