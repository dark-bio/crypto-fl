/// HPKE cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc9180
///
/// Uses X-Wing as the hybrid post-quantum KEM that combines X25519 with
/// ML-KEM-768 for quantum resistance.
library;

import 'src/generated/api/xhpke.dart' as ffi;

/// A private key of the X-Wing hybrid KEM (X25519 + ML-KEM-768).
typedef SecretKey = ffi.XhpkeSecretKey;

/// A public key of the X-Wing hybrid KEM (X25519 + ML-KEM-768).
typedef PublicKey = ffi.XhpkePublicKey;

/// A 32-byte unique identifier for an xHPKE key (SHA256 hash of the raw
/// public key).
typedef Fingerprint = ffi.XhpkeFingerprint;
