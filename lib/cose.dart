// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// COSE wrappers for xDSA and xHPKE.
///
/// https://datatracker.ietf.org/doc/html/rfc9052
/// https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke
///
/// Signatures are COSE_Sign1 envelopes carrying the signer's fingerprint and a
/// timestamp in the protected header. Encryption is COSE_Encrypt0 around a
/// signed envelope, so every message created by [seal] is also signed.
/// Signing, verification, encryption and decryption use an application domain,
/// prefixed with `dark-bio-v1:`, which both sides must agree on.
///
/// Payloads and authenticated messages are plain Dart values. They are encoded
/// with the `cbor` package and must fit the CBOR subset that this package's
/// `cbor` library lists. Decoded payloads come back the way the `cbor` package
/// decodes them, so collections are untyped `List` and `Map` values. Byte
/// strings come back as `List<int>`, which needs `Uint8List.fromList` before
/// it is encoded again.
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/cose.dart' as cose;
/// import 'package:darkbio_crypto/xdsa.dart' as xdsa;
/// import 'package:darkbio_crypto/xhpke.dart' as xhpke;
///
/// void example() {
///   final signer = xdsa.SecretKey.generate();
///   final recipient = xhpke.SecretKey.generate();
///   final domain = utf8.encode('example');
///
///   // Sign a payload, binding a second message supplied separately
///   final signed = cose.sign(msgToEmbed: 'hello', msgToAuth: 'context', signer: signer, domain: domain);
///   final payload = cose.verify<String>(msgToCheck: signed, msgToAuth: 'context', verifier: signer.publicKey(), domain: domain, maxDriftSecs: 60);
///   assert(payload == 'hello');
///
///   // Sign and encrypt to a recipient in one step, then open and verify it back
///   final sealed = cose.seal(msgToSeal: 'secret', msgToAuth: 'context', signer: signer, recipient: recipient.publicKey(), domain: domain);
///   final opened = cose.open<String>(msgToOpen: sealed, msgToAuth: 'context', recipient: recipient, sender: signer.publicKey(), domain: domain, maxDriftSecs: 60);
///   assert(opened == 'secret');
/// }
/// ```
///
/// ## Domain separation and freshness
///
/// Choose distinct domains for distinct application operations. Domains
/// prevent a message for one purpose from being accepted for another; they do
/// not stop repeated use within the same domain. Verification accepts a
/// signature whose timestamp is at most `maxDriftSecs` seconds in the past or
/// future. `null` skips this timestamp check. Applications that require
/// one-time acceptance must also track a message identifier, nonce, or
/// challenge to reject replays.
///
/// ## Wire profile
///
/// Interoperating implementations must match these Dark Bio conventions:
///
/// - Envelopes are untagged COSE_Sign1 and COSE_Encrypt0 arrays. CBOR tags are
///   not accepted. Headers use deterministic integer-key maps.
/// - The private algorithm IDs are `-70000` for xDSA and `-70001` for xHPKE.
///   The protected `kid` is the appropriate public key's fingerprint.
///   Signatures require the private timestamp header `-70002` and name it in
///   `crit`.
/// - For signatures, the Sig_structure `external_aad` is the CBOR encoding of
///   `[bstr("dark-bio-v1:" || domain), msgToAuth]`. An embedded payload is the
///   CBOR encoding of the caller's value.
/// - For [signDetached], the caller's message is authenticated in that
///   `external_aad`, while the Sig_structure payload is an empty byte string
///   and the envelope payload is null. A generic COSE detached-payload API that
///   puts the caller's message in the Sig_structure payload must be adapted to
///   this convention.
/// - For encryption, the Enc_structure `external_aad` is the CBOR encoding of
///   `msgToAuth`; the complete encoded Enc_structure is passed as HPKE AAD.
///   HPKE key derivation uses `"dark-bio-v1:" || domain` as its info. The
///   X-Wing encapsulated key is carried in unprotected header `-4`.
///
/// Here `bstr` denotes a CBOR byte string and `||` denotes byte concatenation.
/// The domain and `msgToAuth` are not included in the returned envelope; both
/// parties must know them or transmit them separately.
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
/// - [domain]: Application domain for separating protocol purposes
///
/// Returns the serialized COSE_Sign1 structure. Throws if [msgToEmbed] or
/// [msgToAuth] does not encode into the supported CBOR subset.
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

/// Creates a COSE_Sign1 digital signature without an embedded payload (the
/// envelope payload is null).
///
/// The caller's message is included in `external_aad`, and the payload in the
/// signature input is empty. See the library's wire profile for
/// interoperability.
///
/// Uses the current system time as the signature timestamp.
///
/// - [msgToAuth]: The message to sign (not embedded in COSE_Sign1)
/// - [signer]: The xDSA secret key to sign with
/// - [domain]: Application domain for separating protocol purposes
///
/// Returns the serialized COSE_Sign1 structure. Throws if [msgToAuth] does not
/// encode into the supported CBOR subset.
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
/// - [domain]: Application domain for separating protocol purposes
/// - [maxDriftSecs]: Maximum allowed timestamp difference in seconds, past or
///   future. A value of n accepts differences up to and including n; `null`
///   skips the check.
///
/// Returns the embedded payload decoded by the `cbor` package, cast to [T].
/// Throws if the envelope is malformed, has no embedded payload, was signed by
/// another key or does not verify. Also throws if its timestamp is further
/// than [maxDriftSecs] from the current time.
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
/// - [domain]: Application domain for separating protocol purposes
/// - [maxDriftSecs]: Maximum allowed timestamp difference in seconds, past or
///   future. A value of n accepts differences up to and including n; `null`
///   skips the check.
///
/// Throws if the envelope is malformed, embeds a payload, was signed by
/// another key or does not verify. Also throws if its timestamp is further
/// than [maxDriftSecs] from the current time.
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
/// - [signature]: The serialized COSE_Sign1 structure
///
/// Returns the signer's fingerprint from the protected header's `kid` field.
/// Throws if the envelope is malformed.
xdsa.Fingerprint signer({required Uint8List signature}) =>
    xdsa.FingerprintInternal.wrap(ffi.coseSigner(signature: signature));

/// Extracts the embedded payload from a COSE_Sign1 signature without
/// verifying it.
///
/// The payload is unauthenticated and must not be trusted until verified with
/// [verify]. Use [signer] to extract the signer's fingerprint for key lookup.
///
/// - [signature]: The serialized COSE_Sign1 structure
///
/// Returns the embedded payload decoded by the `cbor` package, cast to [T].
/// Throws if the envelope is malformed or has no embedded payload.
T peek<T>({required Uint8List signature}) =>
    _decode(ffi.cosePeek(signature: signature)) as T;

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 message without
/// decrypting it.
///
/// This allows looking up the appropriate decryption key before attempting
/// full decryption.
///
/// - [ciphertext]: The serialized COSE_Encrypt0 structure
///
/// Returns the recipient's fingerprint from the protected header's `kid` field.
/// Throws if the envelope is malformed.
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
/// Returns the serialized COSE_Encrypt0 structure. Throws if [msgToAuth] does
/// not encode into the supported CBOR subset.
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
/// extract the signer's fingerprint, then [verify] to verify.
///
/// - [msgToOpen]: The serialized COSE_Encrypt0 structure
/// - [msgToAuth]: The same additional authenticated data used during sealing
/// - [recipient]: The xHPKE secret key to decrypt with
/// - [domain]: Application domain for HPKE key derivation
///
/// Returns the decrypted COSE_Sign1 structure (not yet verified). Throws if
/// the envelope is malformed, was encrypted to another key, or does not
/// decrypt under [recipient], [msgToAuth] and [domain].
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
/// COSE_Sign1. Throws if [msgToSeal] or [msgToAuth] does not encode into the
/// supported CBOR subset.
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
/// - [maxDriftSecs]: Maximum allowed timestamp difference in seconds, past or
///   future. A value of n accepts differences up to and including n; `null`
///   skips the check.
///
/// Returns the payload decoded by the `cbor` package, cast to [T]. Throws if
/// decryption fails as in [decrypt], or verification fails as in [verify].
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
