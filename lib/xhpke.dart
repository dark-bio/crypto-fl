// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// HPKE cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc9180
///
/// Uses X-Wing as the hybrid post-quantum KEM that combines X25519 with
/// ML-KEM-768 for quantum resistance.
library;

import 'dart:typed_data';

import 'src/generated/api/xhpke.dart' as ffi;
import 'xdsa.dart' as xdsa;

/// A private key of the X-Wing hybrid KEM (X25519 + ML-KEM-768).
class SecretKey {
  final ffi.XhpkeSecretKey _inner;
  SecretKey._(this._inner);

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.XhpkeSecretKey.generate());

  /// Converts a 32-byte seed into a private key.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.XhpkeSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.XhpkeSecretKey.fromDer(der: der));

  /// Parses a PEM string into a private key.
  static SecretKey fromPem(String pem) =>
      SecretKey._(ffi.XhpkeSecretKey.fromPem(pem: pem));

  /// Retrieves the public counterpart of the secret key.
  PublicKey publicKey() => PublicKey._(_inner.publicKey());

  /// Returns a 256-bit unique identifier for this key. For HPKE, that is the
  /// SHA256 hash of the raw public key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Consumes a standalone cryptographic construct encrypted to this secret
  /// key. The method will deconstruct the given encapsulated key and ciphertext
  /// and will also verify the authenticity of the (unencrypted) message-to-auth
  /// (not included in the ciphertext).
  ///
  /// Note: X-Wing uses Base mode (no sender authentication). The sender's
  /// identity cannot be verified from the ciphertext alone.
  ///
  /// - [sessionKey]: The 1120-byte encapsulated session key from [PublicKey.seal]
  /// - [msgToOpen]: The ciphertext to decrypt
  /// - [msgToAuth]: Additional authenticated data (must match what was used in seal)
  /// - [domain]: Application-specific domain separator
  Uint8List open({
    required Uint8List sessionKey,
    required Uint8List msgToOpen,
    required Uint8List msgToAuth,
    required Uint8List domain,
  }) => _inner.open(
    sessionKey: sessionKey,
    msgToOpen: msgToOpen,
    msgToAuth: msgToAuth,
    domain: domain,
  );

  /// Converts a private key into a 32-byte seed.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes a private key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes a private key into a PEM string.
  String toPem() => _inner.toPem();
}

/// A public key of the X-Wing hybrid KEM (X25519 + ML-KEM-768).
class PublicKey {
  final ffi.XhpkePublicKey _inner;
  PublicKey._(this._inner);

  /// Converts a 1216-byte array into a public key.
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.XhpkePublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.XhpkePublicKey.fromDer(der: der));

  /// Parses a PEM string into a public key.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.XhpkePublicKey.fromPem(pem: pem));

  /// Parses a public key from a DER-encoded certificate, verifying the xDSA
  /// signature.
  ///
  /// Returns a tuple of (key, notBefore, notAfter) where notBefore and notAfter
  /// are Unix timestamps in seconds defining the certificate validity period.
  static (PublicKey, BigInt, BigInt) fromCertDer(
    Uint8List der, {
    required xdsa.PublicKey signer,
  }) {
    final (key, notBefore, notAfter) = ffi.XhpkePublicKey.fromCertDer(
      der: der,
      signer: signer.inner,
    );
    return (PublicKey._(key), notBefore, notAfter);
  }

  /// Parses a public key from a PEM-encoded certificate, verifying the xDSA
  /// signature.
  ///
  /// Returns a tuple of (key, notBefore, notAfter) where notBefore and notAfter
  /// are Unix timestamps in seconds defining the certificate validity period.
  static (PublicKey, BigInt, BigInt) fromCertPem(
    String pem, {
    required xdsa.PublicKey signer,
  }) {
    final (key, notBefore, notAfter) = ffi.XhpkePublicKey.fromCertPem(
      pem: pem,
      signer: signer.inner,
    );
    return (PublicKey._(key), notBefore, notAfter);
  }

  /// Returns a 256-bit unique identifier for this key. For HPKE, that is the
  /// SHA256 hash of the raw public key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Encrypts a message to this public key.
  ///
  /// Returns a tuple of (sessionKey, ciphertext) where:
  /// - sessionKey is a 1120-byte encapsulated key needed for decryption
  /// - ciphertext is the encrypted message
  ///
  /// - [msgToSeal]: The plaintext to encrypt
  /// - [msgToAuth]: Additional authenticated data (not encrypted, but bound)
  /// - [domain]: Application-specific domain separator
  (Uint8List, Uint8List) seal({
    required Uint8List msgToSeal,
    required Uint8List msgToAuth,
    required Uint8List domain,
  }) => _inner.seal(msgToSeal: msgToSeal, msgToAuth: msgToAuth, domain: domain);

  /// Converts a public key into a 1216-byte array.
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
    required xdsa.SecretKey signer,
    required String subjectName,
    required String issuerName,
    required BigInt notBefore,
    required BigInt notAfter,
    required bool isCa,
    int? pathLen,
  }) => _inner.toCertDer(
    signer: signer.inner,
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
    required xdsa.SecretKey signer,
    required String subjectName,
    required String issuerName,
    required BigInt notBefore,
    required BigInt notAfter,
    required bool isCa,
    int? pathLen,
  }) => _inner.toCertPem(
    signer: signer.inner,
    subjectName: subjectName,
    issuerName: issuerName,
    notBefore: notBefore,
    notAfter: notAfter,
    isCa: isCa,
    pathLen: pathLen,
  );
}

/// A 32-byte unique identifier for an xHPKE key.
class Fingerprint {
  final ffi.XhpkeFingerprint _inner;
  Fingerprint._(this._inner);

  /// Creates a fingerprint from a 32-byte array.
  static Fingerprint fromBytes(Uint8List bytes) =>
      Fingerprint._(ffi.XhpkeFingerprint.fromBytes(bytes: bytes));

  /// Converts a fingerprint into a 32-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Returns the fingerprint as a hex string.
  String toHex() => _inner.toHex();
}

// Internal accessors for cross-package use (e.g., cose.dart)
extension SecretKeyInternal on SecretKey {
  ffi.XhpkeSecretKey get inner => _inner;
}

extension PublicKeyInternal on PublicKey {
  ffi.XhpkePublicKey get inner => _inner;
}

extension FingerprintInternal on Fingerprint {
  static Fingerprint wrap(ffi.XhpkeFingerprint inner) => Fingerprint._(inner);
}
