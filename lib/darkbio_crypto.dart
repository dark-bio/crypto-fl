// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Post-quantum cryptography for Flutter, backed by the Rust `darkbio-crypto`
/// crate through FFI.
///
/// Call [init] once, before anything else in this package. Every other call is
/// synchronous and throws on failure. A slow call, such as an Argon2 derivation
/// with large costs, blocks the calling isolate until it finishes.
///
/// Each primitive lives in its own library, imported with a prefix:
///
/// - `xdsa`: composite ML-DSA-65 and Ed25519 signatures
/// - `xhpke`: X-Wing hybrid public key encryption
/// - `cose`: signed and encrypted COSE envelopes over xDSA and xHPKE
/// - `cwt`: CBOR Web Tokens with CWT and EAT claims
/// - `cbor`: validation of the CBOR subset that `cose` and `cwt` accept
/// - `rsa`: RSA-2048 signatures with SHA-256
/// - `stream`: STREAM authenticated encryption with ChaCha20-Poly1305
/// - `argon2`: password based key derivation
/// - `hkdf`: HKDF-SHA256 key derivation
/// - `rand`: random bytes from the operating system
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/darkbio_crypto.dart' as darkbio;
/// import 'package:darkbio_crypto/xdsa.dart' as xdsa;
///
/// Future<void> main() async {
///   // Load the native library once, before any other call
///   await darkbio.init();
///
///   final secret = xdsa.SecretKey.generate();
///   final signature = secret.sign(utf8.encode('hello'));
///   secret.publicKey().verify(utf8.encode('hello'), signature);
/// }
/// ```
library;

import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import 'src/generated/frb_generated.dart';

/// Loads the native library behind this package.
///
/// Await it once, before any other call into this package. Calling it a
/// second time throws.
Future<void> init() async {
  ExternalLibrary? lib;
  if (Platform.isIOS || Platform.isMacOS) {
    lib = ExternalLibrary.process(iKnowHowToUseIt: true);
  }
  await RustLib.init(externalLibrary: lib);
}
