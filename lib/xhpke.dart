// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// HPKE cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc9180
///
/// Messages are encrypted to a public key with X-Wing, a hybrid of ML-KEM-768
/// and X25519, and sealed with ChaCha20-Poly1305. Encryption and decryption use
/// an application domain, prefixed with `dark-bio-v1:`, which both sides must
/// agree on. The ciphertext also authenticates a second message that must be
/// supplied separately.
///
/// A [Sender] and [Receiver] pair shares one encapsulated key across many
/// messages, which must be opened in the order they were sealed. The domain is
/// fixed when the pair is created.
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/xhpke.dart' as xhpke;
///
/// void example() {
///   final secret = xhpke.SecretKey.generate();
///   final domain = utf8.encode('example');
///   final header = utf8.encode('header');
///
///   final (encapKey, ciphertext) = secret.publicKey().seal(msgToSeal: utf8.encode('secret'), msgToAuth: header, domain: domain);
///   final plaintext = secret.open(sessionKey: encapKey, msgToOpen: ciphertext, msgToAuth: header, domain: domain);
///   assert(utf8.decode(plaintext) == 'secret');
///
///   // Many messages under one encapsulated key, opened in the order sealed
///   final (sender, senderKey) = secret.publicKey().newSender(domain: domain);
///   final receiver = secret.newReceiver(encapKey: senderKey, domain: domain);
///   final message = sender.seal(msgToSeal: utf8.encode('first'), msgToAuth: header);
///   assert(utf8.decode(receiver.open(msgToOpen: message, msgToAuth: header)) == 'first');
/// }
/// ```
library;

import 'dart:typed_data';

import 'package:flutter/foundation.dart' show listEquals;

import 'src/generated/api/xhpke.dart' as ffi;

/// An X-Wing private key for decrypting HPKE messages.
class SecretKey {
  final ffi.XhpkeSecretKey _inner;
  SecretKey._(this._inner);

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.XhpkeSecretKey.generate());

  /// Converts a 32-byte seed into a private key.
  ///
  /// Throws if [bytes] is not 32 bytes long.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.XhpkeSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  ///
  /// Throws if [der] is not a PKCS #8 v1 encoded X-Wing private key, or if
  /// bytes follow it.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.XhpkeSecretKey.fromDer(der: der));

  /// Parses a PEM string into a private key.
  ///
  /// Throws if [pem] is not a single `PRIVATE KEY` block holding an X-Wing
  /// private key. The block starts at the first byte, uses strict base64 and
  /// ends all its lines in LF or all in CRLF.
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
  /// X-Wing is used in HPKE's base mode, which does not authenticate the
  /// sender, so the ciphertext alone does not prove who sent it.
  ///
  /// - [sessionKey]: The 1120-byte encapsulated session key from [PublicKey.seal]
  /// - [msgToOpen]: The ciphertext to decrypt
  /// - [msgToAuth]: Additional authenticated data (must match what was used in seal)
  /// - [domain]: Application domain, the same as the sender's
  ///
  /// Throws if [sessionKey] is not 1120 bytes long, or if decryption fails.
  /// A wrong key, a tampered ciphertext and a mismatched [msgToAuth] or
  /// [domain] all fail alike.
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

  /// Creates an HPKE receiver context for multi-message decryption using
  /// the encapsulated key from [PublicKey.newSender].
  ///
  /// Messages must be decrypted in the same order they were encrypted. X-Wing
  /// is used in HPKE's base mode, which does not authenticate the sender, so
  /// the context alone does not prove who sent the messages.
  ///
  /// - [encapKey]: The 1120-byte encapsulated key from [PublicKey.newSender]
  /// - [domain]: Application domain, the same as the sender's
  ///
  /// Throws if [encapKey] is not 1120 bytes long or not a valid encapsulated
  /// key.
  Receiver newReceiver({
    required Uint8List encapKey,
    required Uint8List domain,
  }) => Receiver._(_inner.newReceiver(encapKey: encapKey, domain: domain));

  /// Converts a private key into a 32-byte seed.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes a private key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes a private key into a PEM string.
  String toPem() => _inner.toPem();
}

/// An X-Wing public key for encrypting HPKE messages.
class PublicKey {
  final ffi.XhpkePublicKey _inner;
  PublicKey._(this._inner);

  /// Converts a 1216-byte array into a public key.
  ///
  /// Throws if [bytes] is not 1216 bytes long, or if a coefficient of its
  /// ML-KEM-768 key falls outside the valid range [0, 3329).
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.XhpkePublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  ///
  /// Throws if [der] is not a SubjectPublicKeyInfo encoded X-Wing public key,
  /// or if bytes follow it.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.XhpkePublicKey.fromDer(der: der));

  /// Parses a PEM string into a public key.
  ///
  /// Throws if [pem] is not a single `PUBLIC KEY` block holding an X-Wing
  /// public key. The block starts at the first byte, uses strict base64 and
  /// ends all its lines in LF or all in CRLF.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.XhpkePublicKey.fromPem(pem: pem));

  /// Returns a 256-bit unique identifier for this key. For HPKE, that is the
  /// SHA256 hash of the raw public key.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Creates an HPKE sender context for multi-message encryption.
  ///
  /// Returns the sender context and a 1120-byte encapsulated key that must
  /// be transmitted to the recipient for [SecretKey.newReceiver].
  ///
  /// Messages encrypted with the returned context must be decrypted in order
  /// by the corresponding receiver. X-Wing is used in HPKE's base mode, which
  /// does not authenticate the sender, so the recipient cannot tell who sent
  /// them from the context alone.
  ///
  /// - [domain]: Application domain, the same as the recipient's
  (Sender, Uint8List) newSender({required Uint8List domain}) {
    final (sender, encapKey) = _inner.newSender(domain: domain);
    return (Sender._(sender), encapKey);
  }

  /// Creates a standalone cryptographic construct encrypted to this public
  /// key. The construct will contain the given message-to-seal (encrypted) and
  /// also an authenticity proof for the (unencrypted) message-to-auth (message
  /// not included).
  ///
  /// Returns the 1120-byte encapsulated session key and the ciphertext.
  /// Opening them with [SecretKey.open] needs both, along with [msgToAuth] and
  /// [domain]. X-Wing is used in HPKE's base mode, which does not authenticate
  /// the sender, so the recipient cannot tell who sent the ciphertext from it
  /// alone.
  ///
  /// - [msgToSeal]: The plaintext to encrypt
  /// - [msgToAuth]: Additional authenticated data (not encrypted, but bound)
  /// - [domain]: Application domain, the same as the recipient's
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
}

/// A 256-bit unique identifier for an xHPKE key.
class Fingerprint {
  final ffi.XhpkeFingerprint _inner;
  Fingerprint._(this._inner);

  /// Creates a fingerprint from a 32-byte array.
  ///
  /// Throws if [bytes] is not 32 bytes long.
  static Fingerprint fromBytes(Uint8List bytes) =>
      Fingerprint._(ffi.XhpkeFingerprint.fromBytes(bytes: bytes));

  /// Converts a fingerprint into a 32-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Whether [other] is an xHPKE fingerprint with the same bytes.
  @override
  bool operator ==(Object other) =>
      other is Fingerprint && listEquals(toBytes(), other.toBytes());

  @override
  int get hashCode => Object.hashAll(toBytes());
}

/// A stateful HPKE sender context for multi-message encryption.
///
/// Each call to [seal] encrypts a message using an auto-incrementing nonce,
/// ensuring unique ciphertexts even for identical plaintexts.
///
/// The corresponding [Receiver] must process messages in the same order
/// they were sealed.
class Sender {
  final ffi.XhpkeSender _inner;
  Sender._(this._inner);

  /// Encrypts a message using the next nonce in the sequence.
  ///
  /// - [msgToSeal]: The plaintext to encrypt
  /// - [msgToAuth]: Additional authenticated data (not encrypted, but bound)
  Uint8List seal({
    required Uint8List msgToSeal,
    required Uint8List msgToAuth,
  }) => _inner.seal(msgToSeal: msgToSeal, msgToAuth: msgToAuth);
}

/// A stateful HPKE receiver context for multi-message decryption.
///
/// Each call to [open] decrypts a message using an auto-incrementing nonce.
/// Messages must be provided in the same order they were sealed by the
/// corresponding [Sender].
class Receiver {
  final ffi.XhpkeReceiver _inner;
  Receiver._(this._inner);

  /// Decrypts a message using the next nonce in the sequence.
  ///
  /// - [msgToOpen]: The ciphertext to decrypt
  /// - [msgToAuth]: Additional authenticated data (must match what was used in seal)
  ///
  /// Throws if decryption fails. A tampered or out-of-order ciphertext and a
  /// mismatched [msgToAuth] all fail alike.
  Uint8List open({
    required Uint8List msgToOpen,
    required Uint8List msgToAuth,
  }) => _inner.open(msgToOpen: msgToOpen, msgToAuth: msgToAuth);
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension SecretKeyInternal on SecretKey {
  /// The native key behind this secret key.
  ffi.XhpkeSecretKey get inner => _inner;
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension PublicKeyInternal on PublicKey {
  /// The native key behind this public key.
  ffi.XhpkePublicKey get inner => _inner;
}

/// Wraps native fingerprints for this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension FingerprintInternal on Fingerprint {
  /// Wraps a native fingerprint into a [Fingerprint].
  static Fingerprint wrap(ffi.XhpkeFingerprint inner) => Fingerprint._(inner);
}
