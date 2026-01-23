// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// RSA cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc8017
library;

import 'dart:typed_data';

import 'src/generated/api/rsa.dart' as ffi;

/// A 2048-bit RSA private key usable for signing, with SHA256 as the underlying
/// hash algorithm. Whilst RSA could also be used for encryption, that is not
/// exposed on the API as it's not required by the project.
class SecretKey {
  final ffi.RsaSecretKey _inner;
  SecretKey._(this._inner);

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.RsaSecretKey.generate());

  /// Parses a 520-byte array into a private key.
  ///
  /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
  /// all in big-endian.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.RsaSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.RsaSecretKey.fromDer(der: der));

  /// Parses a PEM string into a private key.
  static SecretKey fromPem(String pem) =>
      SecretKey._(ffi.RsaSecretKey.fromPem(pem: pem));

  /// Retrieves the public counterpart of the secret key.
  PublicKey publicKey() => PublicKey._(_inner.publicKey());

  /// Returns a 256-bit unique identifier for this key. For RSA, that is the
  /// SHA256 hash of the raw (le modulus || le exponent) public key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Creates a digital signature of the message.
  Signature sign(Uint8List message) =>
      Signature._(_inner.sign(message: message));

  /// Serializes a private key into a 520-byte array.
  ///
  /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
  /// all in big-endian.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes a private key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes a private key into a PEM string.
  String toPem() => _inner.toPem();
}

/// A 2048-bit RSA public key usable for verification, with SHA256 as the
/// underlying hash algorithm. Whilst RSA could also be used for decryption,
/// that is not exposed on the API as it's not required by the project.
class PublicKey {
  final ffi.RsaPublicKey _inner;
  PublicKey._(this._inner);

  /// Parses a 264-byte array into a public key.
  ///
  /// Format: n (256 bytes) || e (8 bytes), all in big-endian.
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.RsaPublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.RsaPublicKey.fromDer(der: der));

  /// Parses a PEM string into a public key.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.RsaPublicKey.fromPem(pem: pem));

  /// Returns a 256-bit unique identifier for this key. For RSA, that is the
  /// SHA256 hash of the raw (le modulus || le exponent) public key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Verifies a signature against a message.
  void verify(Uint8List message, Signature signature) =>
      _inner.verify(message: message, signature: signature._inner);

  /// Serializes a public key into a 264-byte array.
  ///
  /// Format: n (256 bytes) || e (8 bytes), all in big-endian.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes a public key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes a public key into a PEM string.
  String toPem() => _inner.toPem();
}

/// A 256-byte RSA digital signature.
class Signature {
  final ffi.RsaSignature _inner;
  Signature._(this._inner);

  /// Creates a signature from a 256-byte array.
  static Signature fromBytes(Uint8List bytes) =>
      Signature._(ffi.RsaSignature.fromBytes(bytes: bytes));

  /// Serializes the signature to a 256-byte array.
  Uint8List toBytes() => _inner.toBytes();
}

/// A 32-byte unique identifier for an RSA key (SHA256 hash of the raw public
/// key in little-endian format: modulus || exponent).
class Fingerprint {
  final ffi.RsaFingerprint _inner;
  Fingerprint._(this._inner);

  /// Creates a fingerprint from a 32-byte array.
  static Fingerprint fromBytes(Uint8List bytes) =>
      Fingerprint._(ffi.RsaFingerprint.fromBytes(bytes: bytes));

  /// Converts a fingerprint into a 32-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Returns the fingerprint as a hex string.
  String toHex() => _inner.toHex();
}

// Internal accessors for cross-package use if needed
extension SecretKeyInternal on SecretKey {
  ffi.RsaSecretKey get inner => _inner;
}

extension PublicKeyInternal on PublicKey {
  ffi.RsaPublicKey get inner => _inner;
}

extension FingerprintInternal on Fingerprint {
  static Fingerprint wrap(ffi.RsaFingerprint inner) => Fingerprint._(inner);
}
