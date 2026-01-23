// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// RSA cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc8017
library;

import 'src/generated/api/rsa.dart' as ffi;

/// A 2048-bit RSA private key usable for signing, with SHA256 as the underlying
/// hash algorithm. Whilst RSA could also be used for encryption, that is not
/// exposed on the API as it's not required by the project.
typedef SecretKey = ffi.RsaSecretKey;

/// A 2048-bit RSA public key usable for verification, with SHA256 as the
/// underlying hash algorithm. Whilst RSA could also be used for decryption,
/// that is not exposed on the API as it's not required by the project.
typedef PublicKey = ffi.RsaPublicKey;

/// A 256-byte RSA digital signature.
typedef Signature = ffi.RsaSignature;

/// A 32-byte unique identifier for an RSA key (SHA256 hash of the raw public
/// key in little-endian format: modulus || exponent).
typedef Fingerprint = ffi.RsaFingerprint;
