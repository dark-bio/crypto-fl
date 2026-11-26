// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! CBOR Web Token issuance and verification for the Dart bindings.

use darkbio_crypto::{cbor, cwt};
use flutter_rust_bridge::frb;

use super::xdsa::{XdsaFingerprint, XdsaPublicKey, XdsaSecretKey};

/// Signs a canonical CBOR claims map with the current COSE timestamp.
#[frb(sync)]
pub fn cwt_issue(
    claims_cbor: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
) -> Result<Vec<u8>, String> {
    cwt::issue(&cbor::Raw(claims_cbor), &signer.inner, &domain).map_err(|e| e.to_string())
}

/// Signs a canonical CBOR claims map with a COSE timestamp in Unix seconds.
#[frb(sync)]
pub fn cwt_issue_at(
    claims_cbor: Vec<u8>,
    signer: &XdsaSecretKey,
    domain: Vec<u8>,
    timestamp: i64,
) -> Result<Vec<u8>, String> {
    cwt::issue_at(&cbor::Raw(claims_cbor), &signer.inner, &domain, timestamp)
        .map_err(|e| e.to_string())
}

/// Verifies the COSE signature and returns the canonical CBOR claims map.
///
/// With a check time in Unix seconds, `nbf` must be present and at most
/// `now`. If present, `exp` must be greater than `now`.
#[frb(sync)]
pub fn cwt_verify(
    token: Vec<u8>,
    verifier: &XdsaPublicKey,
    domain: Vec<u8>,
    now: Option<u64>,
) -> Result<Vec<u8>, String> {
    cwt::verify::<cbor::Raw>(&token, &verifier.inner, &domain, now)
        .map(|claims| claims.0)
        .map_err(|e| e.to_string())
}

/// Extracts the signer's fingerprint from a CWT without verifying.
///
/// The returned data is unauthenticated.
#[frb(sync)]
pub fn cwt_signer(token: Vec<u8>) -> Result<XdsaFingerprint, String> {
    let fp = cwt::signer(&token).map_err(|e| e.to_string())?;
    Ok(XdsaFingerprint { inner: fp })
}

/// Extracts CBOR claims from a CWT without authenticating them.
///
/// Verify the token before trusting the claims.
#[frb(sync)]
pub fn cwt_peek(token: Vec<u8>) -> Result<Vec<u8>, String> {
    let raw: cbor::Raw = cwt::peek(&token).map_err(|e| e.to_string())?;
    cbor::verify(&raw.0).map_err(|err| err.to_string())?;
    Ok(raw.0)
}
