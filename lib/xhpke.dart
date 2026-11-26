// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// X-Wing HPKE encryption.
///
/// https://datatracker.ietf.org/doc/html/rfc9180
/// https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem
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
  /// Native xHPKE secret key handle.
  final ffi.XhpkeSecretKey _inner;

  /// Wraps a native xHPKE secret key.
  SecretKey._(this._inner);

  /// Returns the live native key or throws after disposal.
  ffi.XhpkeSecretKey get _live {
    if (_inner.isDisposed) {
      throw StateError('secret key used after dispose');
    }
    return _inner;
  }

  /// Creates a new, random private key.
  static SecretKey generate() => SecretKey._(ffi.XhpkeSecretKey.generate());

  /// Converts a 32-byte seed into a private key.
  ///
  /// Throws if [bytes] is not 32 bytes long.
  static SecretKey fromBytes(Uint8List bytes) =>
      SecretKey._(ffi.XhpkeSecretKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a private key.
  ///
  /// Throws if [der] is not a PKCS #8 v1-encoded X-Wing private key, or if
  /// bytes follow it.
  static SecretKey fromDer(Uint8List der) =>
      SecretKey._(ffi.XhpkeSecretKey.fromDer(der: der));

  /// Parses one `PRIVATE KEY` PEM block starting at the first character.
  ///
  /// The strict base64 body requires nonempty lines and consistent LF or CRLF
  /// line endings. Throws if [pem] is malformed or holds another kind of key.
  static SecretKey fromPem(String pem) =>
      SecretKey._(ffi.XhpkeSecretKey.fromPem(pem: pem));

  /// Retrieves the public counterpart of the secret key.
  PublicKey publicKey() => PublicKey._(_live.publicKey());

  /// Returns a 256-bit unique identifier for this key, the SHA-256 hash of the
  /// public key bytes.
  Fingerprint fingerprint() => Fingerprint._(_live.fingerprint());

  /// Decrypts [msgToOpen] sealed to this key using [sessionKey] and checks the
  /// authenticated [msgToAuth] under [domain].
  ///
  /// HPKE runs in base mode, which does not authenticate the sender. The
  /// recipient cannot verify who sealed the message.
  ///
  /// - [sessionKey] - The 1120-byte encapsulated session key from
  ///   [PublicKey.seal]
  /// - [msgToOpen] - The ciphertext to decrypt
  /// - [msgToAuth] - The same second message used during sealing
  /// - [domain] - Application domain, matching the sender's
  ///
  /// Throws if [sessionKey] is not 1120 bytes long, or if decryption fails. A
  /// wrong key, tampered ciphertext, or mismatched [msgToAuth] or [domain] all
  /// fail alike.
  Uint8List open({
    required Uint8List sessionKey,
    required Uint8List msgToOpen,
    required Uint8List msgToAuth,
    required Uint8List domain,
  }) => _live.open(
    sessionKey: sessionKey,
    msgToOpen: msgToOpen,
    msgToAuth: msgToAuth,
    domain: domain,
  );

  /// Creates an HPKE receiver context for multi-message decryption using the
  /// encapsulated key from [PublicKey.newSender].
  ///
  /// Messages must be opened in the order the [Sender] sealed them. HPKE runs
  /// in base mode, which does not authenticate the sender, so the recipient
  /// cannot verify who created the context.
  ///
  /// - [encapKey] - The 1120-byte encapsulated key from [PublicKey.newSender]
  /// - [domain] - Application domain, matching the sender's
  ///
  /// Throws if [encapKey] is not 1120 bytes long or is malformed.
  Receiver newReceiver({
    required Uint8List encapKey,
    required Uint8List domain,
  }) => Receiver._(_live.newReceiver(encapKey: encapKey, domain: domain));

  /// Converts the private key into its 32-byte seed.
  Uint8List toBytes() => _live.toBytes();

  /// Serializes the private key into a DER buffer.
  Uint8List toDer() => _live.toDer();

  /// Serializes the private key into a `PRIVATE KEY` PEM block with LF line
  /// endings.
  String toPem() => _live.toPem();

  /// Wipes the decryption key in Rust memory. Subsequent key operations throw
  /// a [StateError]. Disposal is idempotent. Existing receivers and exported
  /// copies, such as from [toBytes], have independent lifetimes. Without
  /// explicit disposal, cleanup depends on garbage collection.
  void dispose() => _inner.dispose();
}

/// An X-Wing public key for encrypting HPKE messages.
class PublicKey {
  /// Native xHPKE public key handle.
  final ffi.XhpkePublicKey _inner;

  /// Wraps a native xHPKE public key.
  PublicKey._(this._inner);

  /// Converts a 1216-byte array into a public key.
  ///
  /// Throws if [bytes] is not 1216 bytes long, or if a coefficient of its
  /// ML-KEM-768 key falls outside [0, 3329).
  static PublicKey fromBytes(Uint8List bytes) =>
      PublicKey._(ffi.XhpkePublicKey.fromBytes(bytes: bytes));

  /// Parses a DER buffer into a public key.
  ///
  /// Throws if [der] is not a SubjectPublicKeyInfo-encoded X-Wing public key,
  /// or if bytes follow it.
  static PublicKey fromDer(Uint8List der) =>
      PublicKey._(ffi.XhpkePublicKey.fromDer(der: der));

  /// Parses one `PUBLIC KEY` PEM block starting at the first character.
  ///
  /// The strict base64 body requires nonempty lines and consistent LF or CRLF
  /// line endings. Throws if [pem] is malformed or holds another kind of key.
  static PublicKey fromPem(String pem) =>
      PublicKey._(ffi.XhpkePublicKey.fromPem(pem: pem));

  /// Returns a 256-bit unique identifier for this key, the SHA-256 hash of the
  /// public key bytes.
  Fingerprint fingerprint() => Fingerprint._(_inner.fingerprint());

  /// Creates an HPKE sender context for multi-message encryption to this
  /// public key.
  ///
  /// Returns the sender context and a 1120-byte encapsulated key to transmit
  /// to the recipient for [SecretKey.newReceiver]. Messages must be opened in
  /// order by the matching [Receiver]. HPKE runs in base mode, which does not
  /// authenticate the sender.
  ///
  /// - [domain] - Application domain, fixed for every message of the context
  (Sender, Uint8List) newSender({required Uint8List domain}) {
    final (sender, encapKey) = _inner.newSender(domain: domain);
    return (Sender._(sender), encapKey);
  }

  /// Encrypts [msgToSeal] to this public key and authenticates [msgToAuth]
  /// under [domain] without including [msgToAuth] in the output.
  ///
  /// Returns the 1120-byte encapsulated session key and the ciphertext.
  /// Opening them with [SecretKey.open] requires both, along with the same
  /// [msgToAuth] and [domain]. HPKE runs in base mode, which does not
  /// authenticate the sender.
  ///
  /// - [msgToSeal] - The plaintext to encrypt
  /// - [msgToAuth] - The message to authenticate but not include
  /// - [domain] - Application domain, which both sides must agree on
  (Uint8List, Uint8List) seal({
    required Uint8List msgToSeal,
    required Uint8List msgToAuth,
    required Uint8List domain,
  }) => _inner.seal(msgToSeal: msgToSeal, msgToAuth: msgToAuth, domain: domain);

  /// Converts the public key into a 1216-byte array.
  Uint8List toBytes() => _inner.toBytes();

  /// Serializes the public key into a DER buffer.
  Uint8List toDer() => _inner.toDer();

  /// Serializes the public key into a `PUBLIC KEY` PEM block with LF line
  /// endings.
  String toPem() => _inner.toPem();

  /// Whether [other] is an xHPKE public key with the same bytes.
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is PublicKey && listEquals(toBytes(), other.toBytes()));

  /// A hash of the encoded public key.
  @override
  int get hashCode => Object.hashAll(toBytes());
}

/// A 256-bit unique identifier for an xHPKE key.
class Fingerprint {
  /// Native xHPKE fingerprint handle.
  final ffi.XhpkeFingerprint _inner;

  /// Wraps a native xHPKE fingerprint.
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
      identical(this, other) ||
      (other is Fingerprint && listEquals(toBytes(), other.toBytes()));

  /// A hash of the fingerprint bytes.
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
  /// Native xHPKE sender context handle.
  final ffi.XhpkeSender _inner;

  /// Wraps a native xHPKE sender context.
  Sender._(this._inner);

  /// Returns the live native sender context or throws after disposal.
  ffi.XhpkeSender get _live {
    if (_inner.isDisposed) {
      throw StateError('sender used after dispose');
    }
    return _inner;
  }

  /// Encrypts a message using the next nonce in the sequence.
  ///
  /// - [msgToSeal] - The plaintext to encrypt
  /// - [msgToAuth] - The message to authenticate but not include
  Uint8List seal({
    required Uint8List msgToSeal,
    required Uint8List msgToAuth,
  }) => _live.seal(msgToSeal: msgToSeal, msgToAuth: msgToAuth);

  /// Wipes the sender's keys in Rust memory. Subsequent sealing calls throw a
  /// [StateError]. Disposal is idempotent. Without explicit disposal, cleanup
  /// depends on garbage collection.
  void dispose() => _inner.dispose();
}

/// A stateful HPKE receiver context for multi-message decryption.
///
/// Each call to [open] decrypts a message using the next nonce in the
/// sequence. Messages must be opened in the order the [Sender] sealed them.
class Receiver {
  /// Native xHPKE receiver context handle.
  final ffi.XhpkeReceiver _inner;

  /// Wraps a native xHPKE receiver context.
  Receiver._(this._inner);

  /// Returns the live native receiver context or throws after disposal.
  ffi.XhpkeReceiver get _live {
    if (_inner.isDisposed) {
      throw StateError('receiver used after dispose');
    }
    return _inner;
  }

  /// Decrypts a message using the next nonce in the sequence.
  ///
  /// - [msgToOpen] - The ciphertext from [Sender.seal]
  /// - [msgToAuth] - The same second message used during sealing
  ///
  /// Throws if decryption fails. A tampered or out-of-order ciphertext and a
  /// mismatched [msgToAuth] all fail alike.
  Uint8List open({
    required Uint8List msgToOpen,
    required Uint8List msgToAuth,
  }) => _live.open(msgToOpen: msgToOpen, msgToAuth: msgToAuth);

  /// Wipes the receiver's keys in Rust memory. Subsequent opening calls throw
  /// a [StateError]. Disposal is idempotent. Without explicit disposal,
  /// cleanup depends on garbage collection.
  void dispose() => _inner.dispose();
}

/// Exposes the native key to this package's own libraries, not meant for
/// applications.
///
/// @nodoc
extension SecretKeyInternal on SecretKey {
  /// The native key behind this secret key.
  ffi.XhpkeSecretKey get inner => _live;
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
