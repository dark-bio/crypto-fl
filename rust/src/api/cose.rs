use flutter_rust_bridge::frb;

use super::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};
use super::xhpke::{XhpkeFingerprint, XhpkePublicKey, XhpkeSecretKey};

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
) -> Vec<u8> {
    darkbio_crypto::cose::sign(
        darkbio_crypto::cbor::Raw(msg_to_embed),
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &domain,
    )
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
) -> Vec<u8> {
    darkbio_crypto::cose::sign_detached(
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &domain,
    )
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
    let raw: darkbio_crypto::cbor::Raw = darkbio_crypto::cose::verify(
        &msg_to_check,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &verifier.inner,
        &domain,
        max_drift_secs,
    )
    .map_err(|e| e.to_string())?;
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
    darkbio_crypto::cose::verify_detached(
        &msg_to_check,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &verifier.inner,
        &domain,
        max_drift_secs,
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
#[frb(sync)]
pub fn cose_encrypt(
    sign1: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkePublicKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cose::encrypt(
        &sign1,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &recipient.inner,
        &domain,
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
/// Returns the decrypted COSE_Sign1 structure (not yet verified).
#[frb(sync)]
pub fn cose_decrypt(
    msg_to_open: Vec<u8>,
    msg_to_auth: Vec<u8>,
    recipient: &XhpkeSecretKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
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
#[frb(sync)]
pub fn cose_seal(
    msg_to_seal: Vec<u8>,
    msg_to_auth: Vec<u8>,
    signer: &XdsaSecretKey,
    recipient: &XhpkePublicKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cose::seal(
        darkbio_crypto::cbor::Raw(msg_to_seal),
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &signer.inner,
        &recipient.inner,
        &domain,
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
    let raw: darkbio_crypto::cbor::Raw = darkbio_crypto::cose::open(
        &msg_to_open,
        darkbio_crypto::cbor::Raw(msg_to_auth),
        &recipient.inner,
        &sender.inner,
        &domain,
        max_drift_secs,
    )
    .map_err(|e| e.to_string())?;
    Ok(raw.0)
}
