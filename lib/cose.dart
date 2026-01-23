// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// COSE wrappers for xDSA and xHPKE.
///
/// https://datatracker.ietf.org/doc/html/rfc8152
/// https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke
library;

import 'dart:typed_data';

import 'package:cbor/simple.dart' as cbor;

import 'src/generated/api/cose.dart' as ffi;
import 'xdsa.dart'
    as xdsa
    show
        SecretKey,
        PublicKey,
        Fingerprint,
        SecretKeyInternal,
        PublicKeyInternal,
        FingerprintInternal;
import 'xhpke.dart'
    as xhpke
    show
        SecretKey,
        PublicKey,
        Fingerprint,
        SecretKeyInternal,
        PublicKeyInternal,
        FingerprintInternal;

Uint8List _encode(Object? value) => Uint8List.fromList(cbor.cbor.encode(value));
Object? _decode(Uint8List bytes) => cbor.cbor.decode(bytes);

/// Creates a COSE_Sign1 digital signature with an embedded payload.
///
/// Uses the current system time as the signature timestamp.
///
/// - [msgToEmbed]: The message to sign (embedded in COSE_Sign1)
/// - [msgToAuth]: Additional authenticated data (not embedded, but signed)
/// - [signer]: The xDSA secret key to sign with
/// - [domain]: Application domain for replay protection
///
/// Returns the serialized COSE_Sign1 structure.
Uint8List sign({
  required Object? msgToEmbed,
  required Object? msgToAuth,
  required xdsa.SecretKey signer,
  required Uint8List domain,
}) => ffi.coseSign(
  msgToEmbed: _encode(msgToEmbed),
  msgToAuth: _encode(msgToAuth),
  signer: signer.inner,
  domain: domain,
);

/// Creates a COSE_Sign1 digital signature without an embedded payload
/// (i.e. payload is empty).
///
/// Uses the current system time as the signature timestamp.
///
/// - [msgToAuth]: The message to sign (not embedded in COSE_Sign1)
/// - [signer]: The xDSA secret key to sign with
/// - [domain]: Application domain for replay protection
///
/// Returns the serialized COSE_Sign1 structure.
Uint8List signDetached({
  required Object? msgToAuth,
  required xdsa.SecretKey signer,
  required Uint8List domain,
}) => ffi.coseSignDetached(
  msgToAuth: _encode(msgToAuth),
  signer: signer.inner,
  domain: domain,
);

/// Validates a COSE_Sign1 digital signature and returns the embedded payload.
///
/// Uses the current system time for drift checking.
///
/// - [msgToCheck]: The serialized COSE_Sign1 structure
/// - [msgToAuth]: The same additional authenticated data used during signing
/// - [verifier]: The xDSA public key to verify against
/// - [domain]: Application domain for replay protection
/// - [maxDriftSecs]: Signatures more in the past or future are rejected
///
/// Returns the CBOR-decoded embedded payload if verification succeeds.
T verify<T>({
  required Uint8List msgToCheck,
  required Object? msgToAuth,
  required xdsa.PublicKey verifier,
  required Uint8List domain,
  int? maxDriftSecs,
}) =>
    _decode(
          ffi.coseVerify(
            msgToCheck: msgToCheck,
            msgToAuth: _encode(msgToAuth),
            verifier: verifier.inner,
            domain: domain,
            maxDriftSecs: maxDriftSecs != null
                ? BigInt.from(maxDriftSecs)
                : null,
          ),
        )
        as T;

/// Validates a COSE_Sign1 digital signature with a detached payload.
///
/// Uses the current system time for drift checking.
///
/// - [msgToCheck]: The serialized COSE_Sign1 structure (with null payload)
/// - [msgToAuth]: The same message used during signing (verified but not embedded)
/// - [verifier]: The xDSA public key to verify against
/// - [domain]: Application domain for replay protection
/// - [maxDriftSecs]: Signatures more in the past or future are rejected
void verifyDetached({
  required Uint8List msgToCheck,
  required Object? msgToAuth,
  required xdsa.PublicKey verifier,
  required Uint8List domain,
  int? maxDriftSecs,
}) => ffi.coseVerifyDetached(
  msgToCheck: msgToCheck,
  msgToAuth: _encode(msgToAuth),
  verifier: verifier.inner,
  domain: domain,
  maxDriftSecs: maxDriftSecs != null ? BigInt.from(maxDriftSecs) : null,
);

/// Extracts the signer's fingerprint from a COSE_Sign1 signature without
/// verifying it.
///
/// This allows looking up the appropriate verification key before attempting
/// full signature verification.
///
/// Returns the signer's fingerprint from the protected header's `kid` field.
xdsa.Fingerprint signer({required Uint8List signature}) =>
    xdsa.FingerprintInternal.wrap(ffi.coseSigner(signature: signature));

/// Extracts the embedded payload from a COSE_Sign1 signature without
/// verifying it.
///
/// **Warning**: This function does NOT verify the signature. The returned
/// payload is unauthenticated and should not be trusted until verified with
/// [verify]. Use [signer] to extract the signer's fingerprint for key lookup.
///
/// Returns the CBOR-decoded payload.
T peek<T>({required Uint8List signature}) =>
    _decode(ffi.cosePeek(signature: signature)) as T;

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 message without
/// decrypting it.
///
/// This allows looking up the appropriate decryption key before attempting
/// full decryption.
///
/// Returns the recipient's fingerprint from the protected header's `kid` field.
xhpke.Fingerprint recipient({required Uint8List ciphertext}) =>
    xhpke.FingerprintInternal.wrap(ffi.coseRecipient(ciphertext: ciphertext));

/// Encrypts an already-signed COSE_Sign1 to a recipient.
///
/// For most use cases, prefer [seal] which signs and encrypts in one step.
/// Use this only when re-encrypting a message (from [decrypt]) to a different
/// recipient without access to the original signer's key.
///
/// - [sign1]: The COSE_Sign1 structure (e.g., from [decrypt])
/// - [msgToAuth]: The same additional authenticated data used during sealing
/// - [recipient]: The xHPKE public key to encrypt to
/// - [domain]: Application domain for HPKE key derivation
///
/// Returns the serialized COSE_Encrypt0 structure.
Uint8List encrypt({
  required Uint8List sign1,
  required Object? msgToAuth,
  required xhpke.PublicKey recipient,
  required Uint8List domain,
}) => ffi.coseEncrypt(
  sign1: sign1,
  msgToAuth: _encode(msgToAuth),
  recipient: recipient.inner,
  domain: domain,
);

/// Decrypts a sealed message without verifying the signature.
///
/// This allows inspecting the signer before verification. Use [signer] to
/// extract the signer's fingerprint, then [verify] or [verifyDetached] to
/// verify.
///
/// - [msgToOpen]: The serialized COSE_Encrypt0 structure
/// - [msgToAuth]: The same additional authenticated data used during sealing
/// - [recipient]: The xHPKE secret key to decrypt with
/// - [domain]: Application domain for HPKE key derivation
///
/// Returns the decrypted COSE_Sign1 structure (not yet verified).
Uint8List decrypt({
  required Uint8List msgToOpen,
  required Object? msgToAuth,
  required xhpke.SecretKey recipient,
  required Uint8List domain,
}) => ffi.coseDecrypt(
  msgToOpen: msgToOpen,
  msgToAuth: _encode(msgToAuth),
  recipient: recipient.inner,
  domain: domain,
);

/// Signs a message then encrypts it to a recipient.
///
/// Uses the current system time as the signature timestamp.
///
/// - [msgToSeal]: The message to sign and encrypt
/// - [msgToAuth]: Additional authenticated data (signed and bound to encryption,
///   but not embedded)
/// - [signer]: The xDSA secret key to sign with
/// - [recipient]: The xHPKE public key to encrypt to
/// - [domain]: Application domain for HPKE key derivation
///
/// Returns the serialized COSE_Encrypt0 structure containing the encrypted
/// COSE_Sign1.
Uint8List seal({
  required Object? msgToSeal,
  required Object? msgToAuth,
  required xdsa.SecretKey signer,
  required xhpke.PublicKey recipient,
  required Uint8List domain,
}) => ffi.coseSeal(
  msgToSeal: _encode(msgToSeal),
  msgToAuth: _encode(msgToAuth),
  signer: signer.inner,
  recipient: recipient.inner,
  domain: domain,
);

/// Decrypts and verifies a sealed message.
///
/// Uses the current system time for drift checking.
///
/// - [msgToOpen]: The serialized COSE_Encrypt0 structure
/// - [msgToAuth]: The same additional authenticated data used during sealing
/// - [recipient]: The xHPKE secret key to decrypt with
/// - [sender]: The xDSA public key to verify the signature against
/// - [domain]: Application domain for HPKE key derivation
/// - [maxDriftSecs]: Signatures more in the past or future are rejected
///
/// Returns the CBOR-decoded payload if decryption and verification succeed.
T open<T>({
  required Uint8List msgToOpen,
  required Object? msgToAuth,
  required xhpke.SecretKey recipient,
  required xdsa.PublicKey sender,
  required Uint8List domain,
  int? maxDriftSecs,
}) =>
    _decode(
          ffi.coseOpen(
            msgToOpen: msgToOpen,
            msgToAuth: _encode(msgToAuth),
            recipient: recipient.inner,
            sender: sender.inner,
            domain: domain,
            maxDriftSecs: maxDriftSecs != null
                ? BigInt.from(maxDriftSecs)
                : null,
          ),
        )
        as T;
