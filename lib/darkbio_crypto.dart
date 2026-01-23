// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Post-quantum cryptography primitives.
///
/// ## Initialization
///
/// Call [init] once at app startup before using any crypto functions:
///
/// ```dart
/// import 'package:darkbio_crypto/darkbio_crypto.dart';
///
/// void main() async {
///   await init();
///   runApp(MyApp());
/// }
/// ```
///
/// ## Usage
///
/// Import individual modules with prefixes:
///
/// ```dart
/// import 'package:darkbio_crypto/xdsa.dart' as xdsa;
/// import 'package:darkbio_crypto/xhpke.dart' as xhpke;
/// import 'package:darkbio_crypto/cose.dart' as cose;
/// import 'package:darkbio_crypto/hkdf.dart' as hkdf;
/// import 'package:darkbio_crypto/rand.dart' as rand;
///
/// // Digital signatures
/// final secret = xdsa.SecretKey.generate();
/// final signature = secret.sign(message: data);
///
/// // Encryption
/// final recipient = xhpke.SecretKey.generate().publicKey();
/// final sealed = cose.seal(signer: secret, recipient: recipient, ...);
///
/// // Key derivation
/// final key = hkdf.key(secret: secret, salt: salt, info: info);
/// ```
///
/// ## Available modules
///
/// - **xdsa**: Composite ML-DSA-65 + Ed25519 signatures (quantum-resistant)
/// - **xhpke**: X-Wing (X25519 + ML-KEM-768) hybrid encryption
/// - **rsa**: RSA-2048 signatures with SHA-256
/// - **cose**: COSE sign, verify, seal, open operations
/// - **hkdf**: HKDF-SHA256 key derivation
/// - **argon2**: Password-based key derivation
/// - **rand**: Cryptographically secure random bytes
/// - **stream**: STREAM encryption with ChaCha20-Poly1305
library;

import 'src/generated/frb_generated.dart';

/// Initializes the crypto library. Call this once at app startup before
/// using any crypto functions.
Future<void> init() => RustLib.init();
