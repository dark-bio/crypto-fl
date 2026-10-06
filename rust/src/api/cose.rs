// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! COSE signatures and sealed envelopes for the Dart bindings.

use flutter_rust_bridge::frb;

use super::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};
use super::xhpke::{XhpkeFingerprint, XhpkePublicKey, XhpkeSecretKey};

/// CosePadding is a sender's policy for the zero bytes appended to the signed
/// envelope inside the encryption.
#[frb(opaque)]
pub struct CosePadding {
    inner: darkbio_crypto::cose::Padding,
}

impl CosePadding {
    /// Creates a policy that adds no padding.
    #[frb(sync)]
    pub fn none() -> Self {
        Self {
            inner: darkbio_crypto::cose::Padding::None,
        }
    }

    /// Creates a policy that pads to the smallest size that fits. Sizes start at
    /// `floor`, and each next one is the previous one plus `1/step` of it,
    /// rounded up.
    #[frb(sync)]
    pub fn buckets(floor: usize, step: usize) -> Self {
        Self {
            inner: darkbio_crypto::cose::Padding::Buckets { floor, step },
        }
    }
}

/// Creates a COSE_Sign1 signature with an embedded payload.
///
/// - `msg_to_embed`: The payload to embed and sign
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `signer`: The private key to sign with
/// - `domain`: Application-specific domain separator
#[frb(sync)]
pub fn cose_sign(
    msg_to_embed: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_embed).map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::sign(
        darkbio_crypto::cbor::Raw(msg_to_embed),
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &domain,
    )
    .map_err(|e| e.to_string())
}

/// Creates a COSE_Sign1 signature with an embedded payload and an explicit
/// timestamp.
///
/// - `msg_to_embed`: The payload to embed and sign
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `signer`: The private key to sign with
/// - `domain`: Application-specific domain separator
/// - `timestamp`: Unix timestamp in seconds to embed in the signature
#[frb(sync)]
pub fn cose_sign_at(
    msg_to_embed: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
    timestamp: i64,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_embed).map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::sign_at(
        darkbio_crypto::cbor::Raw(msg_to_embed),
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &domain,
        timestamp,
    )
    .map_err(|e| e.to_string())
}

/// Creates a COSE_Sign1 signature without an embedded payload (detached mode).
///
/// - `msg_to_auth`: The message to authenticate (external AAD)
/// - `signer`: The private key to sign with
/// - `domain`: Application-specific domain separator
#[frb(sync)]
pub fn cose_sign_detached(
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::sign_detached(
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &domain,
    )
    .map_err(|e| e.to_string())
}

/// Creates a COSE_Sign1 signature without an embedded payload (detached mode)
/// and with an explicit timestamp.
///
/// - `msg_to_auth`: The message to authenticate (external AAD)
/// - `signer`: The private key to sign with
/// - `domain`: Application-specific domain separator
/// - `timestamp`: Unix timestamp in seconds to embed in the signature
#[frb(sync)]
pub fn cose_sign_detached_at(
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
    timestamp: i64,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::sign_detached_at(
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &domain,
        timestamp,
    )
    .map_err(|e| e.to_string())
}

/// Verifies a COSE_Sign1 signature and returns the embedded payload.
///
/// - `msg_to_check`: The COSE_Sign1 structure to verify
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `verifier`: The public key to verify against
/// - `domain`: Application-specific domain separator
/// - `max_drift_secs`: Maximum allowed clock drift (None for no time check)
#[frb(sync)]
pub fn cose_verify(
    msg_to_check: Vec<u8>,
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: Vec<u8>,
    max_drift_secs: Option<u64>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    let raw: darkbio_crypto::cbor::Raw = darkbio_crypto::cose::verify(
        &msg_to_check,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &verifier.inner,
        &domain,
        max_drift_secs,
    )
    .map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&raw.0).map_err(|err| err.to_string())?;
    Ok(raw.0)
}

/// Verifies a COSE_Sign1 signature against an explicit current time and
/// returns the embedded payload.
///
/// - `msg_to_check`: The COSE_Sign1 structure to verify
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `verifier`: The public key to verify against
/// - `domain`: Application-specific domain separator
/// - `max_drift_secs`: Maximum allowed clock drift (None for no time check)
/// - `now`: Unix timestamp in seconds to measure the drift against
#[frb(sync)]
pub fn cose_verify_at(
    msg_to_check: Vec<u8>,
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: Vec<u8>,
    max_drift_secs: Option<u64>,
    now: i64,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    let raw: darkbio_crypto::cbor::Raw = darkbio_crypto::cose::verify_at(
        &msg_to_check,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &verifier.inner,
        &domain,
        max_drift_secs,
        now,
    )
    .map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&raw.0).map_err(|err| err.to_string())?;
    Ok(raw.0)
}

/// Verifies a COSE_Sign1 signature with a detached payload.
///
/// - `msg_to_check`: The COSE_Sign1 structure to verify
/// - `msg_to_auth`: The detached message to authenticate
/// - `verifier`: The public key to verify against
/// - `domain`: Application-specific domain separator
/// - `max_drift_secs`: Maximum allowed clock drift (None for no time check)
#[frb(sync)]
pub fn cose_verify_detached(
    msg_to_check: Vec<u8>,
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: Vec<u8>,
    max_drift_secs: Option<u64>,
) -> Result<(), String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::verify_detached(
        &msg_to_check,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &verifier.inner,
        &domain,
        max_drift_secs,
    )
    .map_err(|e| e.to_string())
}

/// Verifies a COSE_Sign1 signature with a detached payload against an
/// explicit current time.
///
/// - `msg_to_check`: The COSE_Sign1 structure to verify
/// - `msg_to_auth`: The detached message to authenticate
/// - `verifier`: The public key to verify against
/// - `domain`: Application-specific domain separator
/// - `max_drift_secs`: Maximum allowed clock drift (None for no time check)
/// - `now`: Unix timestamp in seconds to measure the drift against
#[frb(sync)]
pub fn cose_verify_detached_at(
    msg_to_check: Vec<u8>,
    msg_to_auth: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: Vec<u8>,
    max_drift_secs: Option<u64>,
    now: i64,
) -> Result<(), String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::verify_detached_at(
        &msg_to_check,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &verifier.inner,
        &domain,
        max_drift_secs,
        now,
    )
    .map_err(|e| e.to_string())
}

/// Extracts the signer's fingerprint from a COSE_Sign1 without verifying.
#[frb(sync)]
pub fn cose_signer(signature: Vec<u8>) -> Result<XdsaFingerprint, String> {
    let fp = darkbio_crypto::cose::signer(&signature).map_err(|e| e.to_string())?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts the embedded payload from a COSE_Sign1 without verifying.
///
/// Warning: This does NOT verify the signature. The returned payload is
/// unauthenticated and should not be trusted until verified with `verify`.
#[frb(sync)]
pub fn cose_peek(signature: Vec<u8>) -> Result<Vec<u8>, String> {
    let raw: darkbio_crypto::cbor::Raw =
        darkbio_crypto::cose::peek(&signature).map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&raw.0).map_err(|err| err.to_string())?;
    Ok(raw.0)
}

/// Extracts the recipient's fingerprint from a COSE_Encrypt0 without decrypting.
#[frb(sync)]
pub fn cose_recipient(ciphertext: Vec<u8>) -> Result<XhpkeFingerprint, String> {
    let fp = darkbio_crypto::cose::recipient(&ciphertext).map_err(|e| e.to_string())?;
    Ok(XhpkeFingerprint { inner: fp })
}

/// Encrypts an already-signed COSE_Sign1 to a recipient.
///
/// For most use cases, prefer `seal` which signs and encrypts in one step.
/// Use this only when re-encrypting a message (from `decrypt`) to a different
/// recipient without access to the original signer's key.
///
/// - `sign1`: The COSE_Sign1 structure (e.g., from `decrypt`)
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE public key to encrypt to
/// - `domain`: Application domain for HPKE key derivation
/// - `padding`: Sender's padding policy, buckets as `(floor, step)` or none
#[frb(sync)]
pub fn cose_encrypt(
    sign1: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkePublicKey,
    domain: Vec<u8>,
    padding: &CosePadding,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::encrypt(
        &sign1,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &recipient.inner,
        &domain,
        &padding.inner,
    )
    .map_err(|e| e.to_string())
}

/// Decrypts a sealed message without verifying the signature.
///
/// This allows inspecting the signer before verification. Use `signer` to
/// extract the signer's fingerprint, then `verify` to verify.
///
/// - `msg_to_open`: The serialized COSE_Encrypt0 structure
/// - `msg_to_auth`: The same additional authenticated data used during sealing
/// - `recipient`: The xHPKE secret key to decrypt with
/// - `domain`: Application domain for HPKE key derivation
///
/// Returns the decrypted COSE_Sign1 structure (not yet verified), stripping
/// trailing zeros and rejecting any nonzero padding byte.
#[frb(sync)]
pub fn cose_decrypt(
    msg_to_open: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::decrypt(
        &msg_to_open,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &recipient.inner,
        &domain,
    )
    .map_err(|e| e.to_string())
}

/// Signs a message then encrypts it to a recipient (sign-then-encrypt).
///
/// - `msg_to_seal`: The payload to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `signer`: The private key to sign with
/// - `recipient`: The public key to encrypt to
/// - `domain`: Application-specific domain separator
/// - `padding`: Sender's padding policy, buckets as `(floor, step)` or none
#[frb(sync)]
pub fn cose_seal(
    msg_to_seal: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    recipient: &XhpkePublicKey,
    domain: Vec<u8>,
    padding: &CosePadding,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_seal).map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::seal(
        darkbio_crypto::cbor::Raw(msg_to_seal),
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &recipient.inner,
        &domain,
        &padding.inner,
    )
    .map_err(|e| e.to_string())
}

/// Signs a message with an explicit timestamp then encrypts it to a recipient
/// (sign-then-encrypt).
///
/// - `msg_to_seal`: The payload to sign and encrypt
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `signer`: The private key to sign with
/// - `recipient`: The public key to encrypt to
/// - `domain`: Application-specific domain separator
/// - `padding`: Sender's padding policy, buckets as `(floor, step)` or none
/// - `timestamp`: Unix timestamp in seconds to embed in the signature
#[frb(sync)]
pub fn cose_seal_at(
    msg_to_seal: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    recipient: &XhpkePublicKey,
    domain: Vec<u8>,
    padding: &CosePadding,
    timestamp: i64,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_seal).map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    darkbio_crypto::cose::seal_at(
        darkbio_crypto::cbor::Raw(msg_to_seal),
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &recipient.inner,
        &domain,
        &padding.inner,
        timestamp,
    )
    .map_err(|e| e.to_string())
}

/// Decrypts and verifies a sealed message.
///
/// - `msg_to_open`: The COSE structure to decrypt and verify
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `recipient`: The private key to decrypt with
/// - `sender`: The public key to verify the signature against
/// - `domain`: Application-specific domain separator
/// - `max_drift_secs`: Maximum allowed clock drift (None for no time check)
#[frb(sync)]
pub fn cose_open(
    msg_to_open: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    sender: &XdsaPublicKey,
    domain: Vec<u8>,
    max_drift_secs: Option<u64>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    let raw: darkbio_crypto::cbor::Raw = darkbio_crypto::cose::open(
        &msg_to_open,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &recipient.inner,
        &sender.inner,
        &domain,
        max_drift_secs,
    )
    .map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&raw.0).map_err(|err| err.to_string())?;
    Ok(raw.0)
}

/// Decrypts and verifies a sealed message against an explicit current time.
///
/// - `msg_to_open`: The COSE structure to decrypt and verify
/// - `msg_to_auth`: Additional authenticated data (external AAD)
/// - `recipient`: The private key to decrypt with
/// - `sender`: The public key to verify the signature against
/// - `domain`: Application-specific domain separator
/// - `max_drift_secs`: Maximum allowed clock drift (None for no time check)
/// - `now`: Unix timestamp in seconds to measure the drift against
#[frb(sync)]
pub fn cose_open_at(
    msg_to_open: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    sender: &XdsaPublicKey,
    domain: Vec<u8>,
    max_drift_secs: Option<u64>,
    now: i64,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&msg_to_auth).map_err(|e| e.to_string())?;

    let raw: darkbio_crypto::cbor::Raw = darkbio_crypto::cose::open_at(
        &msg_to_open,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &recipient.inner,
        &sender.inner,
        &domain,
        max_drift_secs,
        now,
    )
    .map_err(|e| e.to_string())?;
    darkbio_crypto::cbor::verify(&raw.0).map_err(|err| err.to_string())?;
    Ok(raw.0)
}
