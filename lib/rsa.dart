// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// RSA cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc8017
///
/// RSA-2048 with PKCS#1 v1.5 padding over SHA-256, the classical scheme kept
/// for places where a boot ROM or a legacy system dictates it. New designs
/// should use the `xdsa` library. Only 2048-bit moduli with the exponent 65537
/// are accepted, and encryption is deliberately not exposed.
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/rsa.dart' as rsa;
///
/// void example() {
///   final secret = rsa.SecretKey.generate();
///   final signature = secret.sign(utf8.encode('hello'));
///   secret.publicKey().verify(utf8.encode('hello'), signature);
/// }
/// ```
library;

import 'dart:typed_data';

import 'package:flutter/foundation.dart' show listEquals;

import 'src/generated/api/rsa.dart' as ffi;

/// A 2048-bit RSA private key usable for signing, with SHA256 as the underlying
/// hash algorithm. Whilst RSA could also be used for encryption, that is not
/// exposed on the API as it's not required by the project.
class SecretKey {
  final ffi.RsaSecretKey _inner;
  SecretKey._(this._inner);

  /// The native key, refused once disposed, before the bridge allocates
  /// anything for a call on it.
  ffi.RsaSecretKey get _live {
    if (_inner.isDisposed) {
      throw StateError('secret key used after dispose');
    }
    return _inner;
  }

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.RsaSecretKey.generate());

  /// Parses a 520-byte array into a private key.
  ///
  /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
  /// all in big-endian.
  ///
  /// Throws if [bytes] is not 520 bytes long, or does not hold a valid key
  /// with a 2048-bit modulus and the exponent 65537.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.RsaSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  ///
  /// Throws if [der] is not the canonical PKCS #8 v1 encoding of an RSA
  /// private key with a 2048-bit modulus and the exponent 65537.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.RsaSecretKey.fromDer(der: der));

  /// Parses a PEM string into a private key.
  ///
  /// Throws if [pem] is not a single `PRIVATE KEY` block holding such a DER
  /// key. The block starts at the first byte, uses strict base64 and ends all
  /// its lines in LF or all in CRLF.
  static SecretKey fromPem(String pem) =>
      SecretKey._(ffi.RsaSecretKey.fromPem(pem: pem));

  /// Retrieves the public counterpart of the secret key.
  PublicKey publicKey() => PublicKey._(_live.publicKey());

  /// Returns a 256-bit unique identifier for this key. For RSA, that is the
  /// SHA256 hash of the raw (le modulus || le exponent) public key.
  Fingerprint fingerprint() => Fingerprint._(_live.fingerprint());

  /// Creates a digital signature of the message.
  Signature sign(Uint8List message) =>
      Signature._(_live.sign(message: message));

  /// Serializes a private key into a 520-byte array.
  ///
  /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
  /// all in big-endian.
  Uint8List toBytes() => _live.toBytes();

  /// Serializes a private key into a DER buffer.
  Uint8List toDer() => _live.toDer();

  /// Serializes a private key into a PEM string.
  String toPem() => _live.toPem();

  /// Wipes the secret key held in Rust memory. Every later use of this key
  /// throws a [StateError], and disposing it again does nothing. Copies already
  /// exported, such as by [toBytes], are not affected. Without a dispose, the
  /// key is only wiped if the garbage collector finalizes it, which is not
  /// guaranteed.
  void dispose() => _inner.dispose();
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
  ///
  /// Throws if [bytes] is not 264 bytes long, if the modulus is not 2048 bits
  /// or if the exponent is not 65537.
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.RsaPublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  ///
  /// Throws if [der] is not a SubjectPublicKeyInfo encoded RSA public key with
  /// a 2048-bit modulus and the exponent 65537.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.RsaPublicKey.fromDer(der: der));

  /// Parses a PEM string into a public key.
  ///
  /// Throws if [pem] is not a single `PUBLIC KEY` block holding such a DER key.
  /// The block starts at the first byte, uses strict base64 and ends all its
  /// lines in LF or all in CRLF.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.RsaPublicKey.fromPem(pem: pem));

  /// Returns a 256-bit unique identifier for this key. For RSA, that is the
  /// SHA256 hash of the raw (le modulus || le exponent) public key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Verifies a signature against a message.
  ///
  /// Throws if the signature does not verify under this key for [message].
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

/// A 256-byte RSA-2048 digital signature.
class Signature {
  final ffi.RsaSignature _inner;
  Signature._(this._inner);

  /// Creates a signature from a 256-byte array.
  ///
  /// Throws if [bytes] is not 256 bytes long.
  static Signature fromBytes(Uint8List bytes) =>
      Signature._(ffi.RsaSignature.fromBytes(bytes: bytes));

  /// Serializes the signature to a 256-byte array.
  Uint8List toBytes() => _inner.toBytes();
}

/// A 256-bit unique identifier for an RSA key, the SHA256 hash of its raw
/// public key in little-endian format (modulus || exponent).
class Fingerprint {
  final ffi.RsaFingerprint _inner;
  Fingerprint._(this._inner);

  /// Creates a fingerprint from a 32-byte array.
  ///
  /// Throws if [bytes] is not 32 bytes long.
  static Fingerprint fromBytes(Uint8List bytes) =>
      Fingerprint._(ffi.RsaFingerprint.fromBytes(bytes: bytes));

  /// Converts a fingerprint into a 32-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Whether [other] is an RSA fingerprint with the same bytes.
  @override
  bool operator ==(Object other) =>
      other is Fingerprint && listEquals(toBytes(), other.toBytes());

  @override
  int get hashCode => Object.hashAll(toBytes());
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension SecretKeyInternal on SecretKey {
  /// The native key behind this secret key.
  ffi.RsaSecretKey get inner => _live;
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension PublicKeyInternal on PublicKey {
  /// The native key behind this public key.
  ffi.RsaPublicKey get inner => _inner;
}

/// Wraps native fingerprints for this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension FingerprintInternal on Fingerprint {
  /// Wraps a native fingerprint into a [Fingerprint].
  static Fingerprint wrap(ffi.RsaFingerprint inner) => Fingerprint._(inner);
}
