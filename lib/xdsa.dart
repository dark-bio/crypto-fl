// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Composite ML-DSA cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
library;

import 'dart:typed_data';

import 'src/generated/api/xdsa.dart' as ffi;

/// An ML-DSA-65 private key paired with an Ed25519 private key for creating
/// and verifying quantum resistant digital signatures.
class SecretKey {
  final ffi.XdsaSecretKey _inner;
  SecretKey._(this._inner);

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.XdsaSecretKey.generate());

  /// Creates a private key from a 64-byte seed.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.XdsaSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.XdsaSecretKey.fromDer(der: der));

  /// Parses a PEM string into a private key.
  static SecretKey fromPem(String pem) =>
      SecretKey._(ffi.XdsaSecretKey.fromPem(pem: pem));

  /// Retrieves the public counterpart of the secret key.
  PublicKey publicKey() => PublicKey._(_inner.publicKey());

  /// Returns a 256-bit unique identifier for this key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Creates a digital signature of the message.
  Signature sign(Uint8List message) =>
      Signature._(_inner.sign(message: message));

  /// Converts a secret key into a 64-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes a private key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes a private key into a PEM string.
  String toPem() => _inner.toPem();
}

/// An ML-DSA-65 public key paired with an Ed25519 public key for verifying
/// quantum resistant digital signatures.
class PublicKey {
  final ffi.XdsaPublicKey _inner;
  PublicKey._(this._inner);

  /// Converts a 1984-byte array into a public key.
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.XdsaPublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.XdsaPublicKey.fromDer(der: der));

  /// Parses a PEM string into a public key.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.XdsaPublicKey.fromPem(pem: pem));

  /// Parses a public key from a DER-encoded certificate, verifying the signature.
  ///
  /// Returns a tuple of (key, notBefore, notAfter) where notBefore and notAfter
  /// are Unix timestamps in seconds defining the certificate validity period.
  static (PublicKey, BigInt, BigInt) fromCertDer(
    Uint8List der, {
    required PublicKey signer,
  }) {
    final (key, notBefore, notAfter) = ffi.XdsaPublicKey.fromCertDer(
      der: der,
      signer: signer._inner,
    );
    return (PublicKey._(key), notBefore, notAfter);
  }

  /// Parses a public key from a PEM-encoded certificate, verifying the signature.
  ///
  /// Returns a tuple of (key, notBefore, notAfter) where notBefore and notAfter
  /// are Unix timestamps in seconds defining the certificate validity period.
  static (PublicKey, BigInt, BigInt) fromCertPem(
    String pem, {
    required PublicKey signer,
  }) {
    final (key, notBefore, notAfter) = ffi.XdsaPublicKey.fromCertPem(
      pem: pem,
      signer: signer._inner,
    );
    return (PublicKey._(key), notBefore, notAfter);
  }

  /// Returns a 256-bit unique identifier for this key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Verifies a signature against a message.
  void verify(Uint8List message, Signature signature) =>
      _inner.verify(message: message, signature: signature._inner);

  /// Converts a public key into a 1984-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes a public key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes a public key into a PEM string.
  String toPem() => _inner.toPem();

  /// Generates a DER-encoded X.509 certificate for this public key, signed by
  /// the given xDSA secret key with the specified validity period.
  ///
  /// - [signer]: The xDSA secret key to sign the certificate
  /// - [subjectName]: The subject's common name (CN)
  /// - [issuerName]: The issuer's common name (CN)
  /// - [notBefore]: Certificate validity start time (Unix timestamp)
  /// - [notAfter]: Certificate validity end time (Unix timestamp)
  /// - [isCa]: Whether this is a CA certificate
  /// - [pathLen]: Maximum intermediate CAs allowed (only if isCa is true)
  Uint8List toCertDer({
    required SecretKey signer,
    required String subjectName,
    required String issuerName,
    required BigInt notBefore,
    required BigInt notAfter,
    required bool isCa,
    int? pathLen,
  }) => _inner.toCertDer(
    signer: signer._inner,
    subjectName: subjectName,
    issuerName: issuerName,
    notBefore: notBefore,
    notAfter: notAfter,
    isCa: isCa,
    pathLen: pathLen,
  );

  /// Generates a PEM-encoded X.509 certificate for this public key, signed by
  /// the given xDSA secret key with the specified validity period.
  ///
  /// - [signer]: The xDSA secret key to sign the certificate
  /// - [subjectName]: The subject's common name (CN)
  /// - [issuerName]: The issuer's common name (CN)
  /// - [notBefore]: Certificate validity start time (Unix timestamp)
  /// - [notAfter]: Certificate validity end time (Unix timestamp)
  /// - [isCa]: Whether this is a CA certificate
  /// - [pathLen]: Maximum intermediate CAs allowed (only if isCa is true)
  String toCertPem({
    required SecretKey signer,
    required String subjectName,
    required String issuerName,
    required BigInt notBefore,
    required BigInt notAfter,
    required bool isCa,
    int? pathLen,
  }) => _inner.toCertPem(
    signer: signer._inner,
    subjectName: subjectName,
    issuerName: issuerName,
    notBefore: notBefore,
    notAfter: notAfter,
    isCa: isCa,
    pathLen: pathLen,
  );
}

/// A composite ML-DSA-65 + Ed25519 digital signature (3373 bytes).
class Signature {
  final ffi.XdsaSignature _inner;
  Signature._(this._inner);

  /// Creates a signature from a 3373-byte array.
  static Signature fromBytes(Uint8List bytes) =>
      Signature._(ffi.XdsaSignature.fromBytes(bytes: bytes));

  /// Serializes the signature to a 3373-byte array.
  Uint8List toBytes() => _inner.toBytes();
}

/// A 32-byte unique identifier for an xDSA key.
class Fingerprint {
  final ffi.XdsaFingerprint _inner;
  Fingerprint._(this._inner);

  /// Creates a fingerprint from a 32-byte array.
  static Fingerprint fromBytes(Uint8List bytes) =>
      Fingerprint._(ffi.XdsaFingerprint.fromBytes(bytes: bytes));

  /// Converts a fingerprint into a 32-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Returns the fingerprint as a hex string.
  String toHex() => _inner.toHex();
}

// Internal accessors for cross-package use (e.g., cose.dart, xhpke.dart)
extension SecretKeyInternal on SecretKey {
  ffi.XdsaSecretKey get inner => _inner;
}

extension PublicKeyInternal on PublicKey {
  ffi.XdsaPublicKey get inner => _inner;
}

extension FingerprintInternal on Fingerprint {
  static Fingerprint wrap(ffi.XdsaFingerprint inner) => Fingerprint._(inner);
}
