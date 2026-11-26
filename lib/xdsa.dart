// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Composite ML-DSA-65 and Ed25519 digital signatures.
///
/// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
///
/// A key signs a message with ML-DSA-65 and Ed25519 at once, and a signature
/// verifies only if both halves do. Keys and signatures round-trip through
/// fixed-size byte arrays. Keys also support DER and PEM serialization.
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/xdsa.dart' as xdsa;
///
/// void example() {
///   final secret = xdsa.SecretKey.generate();
///   final public = secret.publicKey();
///
///   final signature = secret.sign(utf8.encode('hello'));
///   public.verify(utf8.encode('hello'), signature);
///
///   // A key restored from PEM is the same key
///   final restored = xdsa.PublicKey.fromPem(public.toPem());
///   assert(restored.fingerprint() == public.fingerprint());
/// }
/// ```
library;

import 'dart:typed_data';

import 'package:flutter/foundation.dart' show listEquals;

import 'src/generated/api/xdsa.dart' as ffi;

/// An ML-DSA-65 private key paired with an Ed25519 private key for creating
/// quantum-resistant digital signatures.
class SecretKey {
  /// Native xDSA secret key handle.
  final ffi.XdsaSecretKey _inner;

  /// Wraps a native xDSA secret key.
  SecretKey._(this._inner);

  /// Returns the live native key or throws after disposal.
  ffi.XdsaSecretKey get _live {
    if (_inner.isDisposed) {
      throw StateError('secret key used after dispose');
    }
    return _inner;
  }

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.XdsaSecretKey.generate());

  /// Creates a private key from a 64-byte seed, the ML-DSA-65 seed (32 bytes)
  /// followed by the Ed25519 seed (32 bytes).
  ///
  /// Throws if [bytes] is not 64 bytes long.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.XdsaSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  ///
  /// Throws if [der] is not a PKCS #8 v1-encoded xDSA private key, or if bytes
  /// follow it.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.XdsaSecretKey.fromDer(der: der));

  /// Parses one `PRIVATE KEY` PEM block starting at the first character.
  ///
  /// The strict base64 body requires nonempty lines and consistent LF or CRLF
  /// line endings. Throws if [pem] is malformed or holds another kind of key.
  static SecretKey fromPem(String pem) =>
      SecretKey._(ffi.XdsaSecretKey.fromPem(pem: pem));

  /// Retrieves the public counterpart of the secret key.
  PublicKey publicKey() => PublicKey._(_live.publicKey());

  /// Returns a 256-bit unique identifier for this key.
  Fingerprint fingerprint() => Fingerprint._(_live.fingerprint());

  /// Signs [message] with hedged ML-DSA-65 and Ed25519.
  ///
  /// ML-DSA-65 mixes fresh randomness into each signature, so signing the same
  /// message again can produce different bytes. Both signatures verify.
  Signature sign(Uint8List message) =>
      Signature._(_live.sign(message: message));

  /// Converts the secret key into its 64-byte seed.
  Uint8List toBytes() => _live.toBytes();

  /// Serializes the private key into a DER buffer.
  Uint8List toDer() => _live.toDer();

  /// Serializes the private key into a `PRIVATE KEY` PEM block with LF line
  /// endings.
  String toPem() => _live.toPem();

  /// Wipes the signing key in Rust memory. Subsequent key operations throw a
  /// [StateError]. Disposal is idempotent. Exported copies, such as from
  /// [toBytes], remain owned by the caller. Without explicit disposal, cleanup
  /// depends on garbage collection.
  void dispose() => _inner.dispose();
}

/// An ML-DSA-65 public key paired with an Ed25519 public key for verifying
/// quantum-resistant digital signatures.
class PublicKey {
  /// Native xDSA public key handle.
  final ffi.XdsaPublicKey _inner;

  /// Wraps a native xDSA public key.
  PublicKey._(this._inner);

  /// Converts a 1984-byte array into a public key, the ML-DSA-65 key (1952
  /// bytes) followed by the Ed25519 key (32 bytes).
  ///
  /// Throws if [bytes] is not 1984 bytes long or its Ed25519 key is invalid.
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.XdsaPublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  ///
  /// Throws if [der] is not a SubjectPublicKeyInfo-encoded xDSA public key, or
  /// if bytes follow it.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.XdsaPublicKey.fromDer(der: der));

  /// Parses one `PUBLIC KEY` PEM block starting at the first character.
  ///
  /// The strict base64 body requires nonempty lines and consistent LF or CRLF
  /// line endings. Throws if [pem] is malformed or holds another kind of key.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.XdsaPublicKey.fromPem(pem: pem));

  /// Returns a 256-bit unique identifier for this key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Verifies [signature] against [message].
  ///
  /// Both the ML-DSA-65 and Ed25519 halves must verify, and failures are not
  /// distinguished. Throws if verification fails.
  void verify(Uint8List message, Signature signature) =>
      _inner.verify(message: message, signature: signature._inner);

  /// Converts the public key into a 1984-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes the public key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes the public key into a `PUBLIC KEY` PEM block with LF line
  /// endings.
  String toPem() => _inner.toPem();

  /// Whether [other] is an xDSA public key with the same bytes.
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is PublicKey && listEquals(toBytes(), other.toBytes()));

  /// A hash of the encoded public key.
  @override
  int get hashCode => Object.hashAll(toBytes());
}

/// An ML-DSA-65 signature (3309 bytes) paired with an Ed25519 signature (64
/// bytes), 3373 bytes in total.
class Signature {
  /// Native xDSA signature handle.
  final ffi.XdsaSignature _inner;

  /// Wraps a native xDSA signature.
  Signature._(this._inner);

  /// Creates a signature from a 3373-byte array.
  ///
  /// Throws if [bytes] is not 3373 bytes long.
  static Signature fromBytes(Uint8List bytes) =>
      Signature._(ffi.XdsaSignature.fromBytes(bytes: bytes));

  /// Converts the signature into a 3373-byte array.
  Uint8List toBytes() => _inner.toBytes();
}

/// A 256-bit unique identifier for an xDSA key.
class Fingerprint {
  /// Native xDSA fingerprint handle.
  final ffi.XdsaFingerprint _inner;

  /// Wraps a native xDSA fingerprint.
  Fingerprint._(this._inner);

  /// Creates a fingerprint from a 32-byte array.
  ///
  /// Throws if [bytes] is not 32 bytes long.
  static Fingerprint fromBytes(Uint8List bytes) =>
      Fingerprint._(ffi.XdsaFingerprint.fromBytes(bytes: bytes));

  /// Converts a fingerprint into a 32-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Whether [other] is an xDSA fingerprint with the same bytes.
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is Fingerprint && listEquals(toBytes(), other.toBytes()));

  /// A hash of the fingerprint bytes.
  @override
  int get hashCode => Object.hashAll(toBytes());
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension SecretKeyInternal on SecretKey {
  /// The native key behind this secret key.
  ffi.XdsaSecretKey get inner => _live;
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension PublicKeyInternal on PublicKey {
  /// The native key behind this public key.
  ffi.XdsaPublicKey get inner => _inner;
}

/// Wraps native fingerprints for this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension FingerprintInternal on Fingerprint {
  /// Wraps a native fingerprint into a [Fingerprint].
  static Fingerprint wrap(ffi.XdsaFingerprint inner) => Fingerprint._(inner);
}
