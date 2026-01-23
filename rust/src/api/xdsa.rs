// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use flutter_rust_bridge::frb;

/// XdsaSecretKey is a composite ML-DSA-65 + Ed25519 private key for creating
/// quantum-resistant digital signatures.
#[frb(opaque)]
pub struct XdsaSecretKey {
    pub(crate) inner: darkbio_crypto::xdsa::SecretKey,
}

impl XdsaSecretKey {
    /// Generates a new random private key.
    #[frb(sync)]
    pub fn generate() -> Self {
        Self {
            inner: darkbio_crypto::xdsa::SecretKey::generate(),
        }
    }

    /// Creates a private key from a 64-byte seed.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| "Invalid key length, expected 64 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xdsa::SecretKey::from_bytes(&bytes_array),
        })
    }

    /// Parses a DER-encoded private key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xdsa::SecretKey::from_der(&der).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded private key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xdsa::SecretKey::from_pem(&pem).map_err(|e| e.to_string())?,
        })
    }

    /// Serializes the private key to a 64-byte seed.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Serializes the private key to DER format.
    #[frb(sync)]
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_der()
    }

    /// Serializes the private key to PEM format.
    #[frb(sync)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    /// Returns the public key corresponding to this private key.
    #[frb(sync)]
    pub fn public_key(&self) -> XdsaPublicKey {
        XdsaPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    #[frb(sync)]
    pub fn fingerprint(&self) -> XdsaFingerprint {
        XdsaFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Signs a message, returning a composite signature.
    #[frb(sync)]
    pub fn sign(&self, message: Vec<u8>) -> XdsaSignature {
        XdsaSignature {
            inner: self.inner.sign(&message),
        }
    }
}

/// XdsaPublicKey is a composite ML-DSA-65 + Ed25519 public key for verifying
/// quantum-resistant digital signatures.
#[frb(opaque)]
pub struct XdsaPublicKey {
    pub(crate) inner: darkbio_crypto::xdsa::PublicKey,
}

impl XdsaPublicKey {
    /// Creates a public key from a 1984-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 1984] = bytes
            .try_into()
            .map_err(|_| "Invalid key length, expected 1984 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xdsa::PublicKey::from_bytes(&bytes_array)
                .map_err(|e| e.to_string())?,
        })
    }

    /// Parses a DER-encoded public key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xdsa::PublicKey::from_der(&der).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded public key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xdsa::PublicKey::from_pem(&pem).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a public key from a DER-encoded certificate, verifying the signature.
    /// Returns the key along with validity start and end timestamps (Unix seconds).
    #[frb(sync)]
    pub fn from_cert_der(der: Vec<u8>, signer: &XdsaPublicKey) -> Result<(Self, u64, u64), String> {
        let (key, start, until) =
            darkbio_crypto::xdsa::PublicKey::from_cert_der(&der, signer.inner.clone())
                .map_err(|e| e.to_string())?;
        Ok((Self { inner: key }, start, until))
    }

    /// Parses a public key from a PEM-encoded certificate, verifying the signature.
    /// Returns the key along with validity start and end timestamps (Unix seconds).
    #[frb(sync)]
    pub fn from_cert_pem(pem: String, signer: &XdsaPublicKey) -> Result<(Self, u64, u64), String> {
        let (key, start, until) =
            darkbio_crypto::xdsa::PublicKey::from_cert_pem(&pem, signer.inner.clone())
                .map_err(|e| e.to_string())?;
        Ok((Self { inner: key }, start, until))
    }

    /// Serializes the public key to a 1984-byte array.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Serializes the public key to DER format.
    #[frb(sync)]
    pub fn to_der(&self) -> Vec<u8> {
        self.inner.to_der()
    }

    /// Serializes the public key to PEM format.
    #[frb(sync)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem()
    }

    /// Generates a DER-encoded X.509 certificate for this public key,
    /// signed by the given xDSA secret key with the specified validity period.
    ///
    /// - `signer`: The xDSA secret key to sign the certificate
    /// - `subject_name`: The subject's common name (CN)
    /// - `issuer_name`: The issuer's common name (CN)
    /// - `not_before`: Certificate validity start time (Unix timestamp)
    /// - `not_after`: Certificate validity end time (Unix timestamp)
    /// - `is_ca`: Whether this is a CA certificate
    /// - `path_len`: Maximum intermediate CAs allowed (only if is_ca is true)
    #[frb(sync)]
    #[allow(clippy::too_many_arguments)]
    pub fn to_cert_der(
        &self,
        signer: &super::xdsa::XdsaSecretKey,
        subject_name: String,
        issuer_name: String,
        not_before: u64,
        not_after: u64,
        is_ca: bool,
        path_len: Option<u8>,
    ) -> Result<Vec<u8>, String> {
        let params = darkbio_crypto::x509::Params {
            subject_name: &subject_name,
            issuer_name: &issuer_name,
            not_before,
            not_after,
            is_ca,
            path_len,
        };
        self.inner
            .to_cert_der(&signer.inner, &params)
            .map_err(|e| e.to_string())
    }

    /// Generates a PEM-encoded X.509 certificate for this public key,
    /// signed by the given xDSA secret key with the specified validity period.
    ///
    /// - `signer`: The xDSA secret key to sign the certificate
    /// - `subject_name`: The subject's common name (CN)
    /// - `issuer_name`: The issuer's common name (CN)
    /// - `not_before`: Certificate validity start time (Unix timestamp)
    /// - `not_after`: Certificate validity end time (Unix timestamp)
    /// - `is_ca`: Whether this is a CA certificate
    /// - `path_len`: Maximum intermediate CAs allowed (only if is_ca is true)
    #[frb(sync)]
    #[allow(clippy::too_many_arguments)]
    pub fn to_cert_pem(
        &self,
        signer: &super::xdsa::XdsaSecretKey,
        subject_name: String,
        issuer_name: String,
        not_before: u64,
        not_after: u64,
        is_ca: bool,
        path_len: Option<u8>,
    ) -> Result<String, String> {
        let params = darkbio_crypto::x509::Params {
            subject_name: &subject_name,
            issuer_name: &issuer_name,
            not_before,
            not_after,
            is_ca,
            path_len,
        };
        self.inner
            .to_cert_pem(&signer.inner, &params)
            .map_err(|e| e.to_string())
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    #[frb(sync)]
    pub fn fingerprint(&self) -> XdsaFingerprint {
        XdsaFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Verifies a signature against a message.
    #[frb(sync)]
    pub fn verify(&self, message: Vec<u8>, signature: &XdsaSignature) -> Result<(), String> {
        self.inner
            .verify(&message, &signature.inner)
            .map_err(|e| e.to_string())
    }
}

/// XdsaSignature is a composite ML-DSA-65 + Ed25519 digital signature.
#[frb(opaque)]
pub struct XdsaSignature {
    pub(crate) inner: darkbio_crypto::xdsa::Signature,
}

impl XdsaSignature {
    /// Creates a signature from a 3373-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 3373] = bytes
            .try_into()
            .map_err(|_| "Invalid signature length, expected 3373 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xdsa::Signature::from_bytes(&bytes_array),
        })
    }

    /// Serializes the signature to a 3373-byte array.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

/// XdsaFingerprint is a 32-byte unique identifier for an xDSA key.
#[frb(opaque)]
pub struct XdsaFingerprint {
    pub(crate) inner: darkbio_crypto::xdsa::Fingerprint,
}

impl XdsaFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Invalid fingerprint length, expected 32 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xdsa::Fingerprint::from_bytes(&bytes_array),
        })
    }

    /// Serializes the fingerprint to a 32-byte array.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}
