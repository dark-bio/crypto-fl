// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use flutter_rust_bridge::frb;

use super::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};

/// Issues a CWT by signing pre-encoded CBOR claims with COSE Sign1.
///
/// - `claims_cbor`: CBOR-encoded claims map
/// - `signer`: The xDSA secret key to sign with
/// - `domain`: Application-specific domain separator
#[frb(sync)]
pub fn cwt_issue(
    claims_cbor: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    darkbio_crypto::cbor::verify(&claims_cbor).map_err(|e| e.to_string())?;

    darkbio_crypto::cwt::issue(
        &darkbio_crypto::cbor::Raw(claims_cbor),
        &signer.inner,
        &domain,
    )
    .map_err(|e| e.to_string())
}

/// Verifies a CWT's COSE signature and temporal validity, returning
/// the raw CBOR-encoded claims.
///
/// When `now` is provided, temporal claims are validated: nbf must be
/// present and `nbf <= now`, and if exp is present then `now < exp`.
/// When `now` is `None`, temporal validation is skipped.
///
/// - `token`: The serialized CWT
/// - `verifier`: The xDSA public key to verify against
/// - `domain`: Application-specific domain separator
/// - `now`: Current Unix timestamp for temporal validation (None to skip)
#[frb(sync)]
pub fn cwt_verify(
    token: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: Vec<u8>,
    now: Option<u64>,
) -> Result<Vec<u8>, String> {
    let raw: darkbio_crypto::cbor::Raw =
        darkbio_crypto::cwt::verify(&token, &verifier.inner, &domain, now)
            .map_err(|e| e.to_string())?;
    Ok(raw.0)
}

/// Extracts the signer's fingerprint from a CWT without verifying.
///
/// The returned data is unauthenticated.
#[frb(sync)]
pub fn cwt_signer(token: Vec<u8>) -> Result<XdsaFingerprint, String> {
    let fp = darkbio_crypto::cwt::signer(&token).map_err(|e| e.to_string())?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts and decodes claims from a CWT without verifying the signature.
///
/// **Warning**: The returned payload is unauthenticated and should not be
/// trusted until verified with `cwt_verify`.
#[frb(sync)]
pub fn cwt_peek(token: Vec<u8>) -> Result<Vec<u8>, String> {
    let raw: darkbio_crypto::cbor::Raw =
        darkbio_crypto::cwt::peek(&token).map_err(|e| e.to_string())?;
    Ok(raw.0)
}
