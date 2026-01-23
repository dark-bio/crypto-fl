// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use flutter_rust_bridge::frb;

/// RsaSecretKey is a 2048-bit RSA private key for creating digital signatures
/// using SHA-256 as the underlying hash algorithm.
#[frb(opaque)]
pub struct RsaSecretKey {
    pub(crate) inner: darkbio_crypto::rsa::SecretKey,
}

impl RsaSecretKey {
    /// Generates a new random private key.
    #[frb(sync)]
    pub fn generate() -> Self {
        Self {
            inner: darkbio_crypto::rsa::SecretKey::generate(),
        }
    }

    /// Creates a private key from a 520-byte array.
    /// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes).
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 520] = bytes
            .try_into()
            .map_err(|_| "Invalid key length, expected 520 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::rsa::SecretKey::from_bytes(&bytes_array)
                .map_err(|e| e.to_string())?,
        })
    }

    /// Parses a DER-encoded private key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::rsa::SecretKey::from_der(&der).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded private key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::rsa::SecretKey::from_pem(&pem).map_err(|e| e.to_string())?,
        })
    }

    /// Serializes the private key to a 520-byte array.
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
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    #[frb(sync)]
    pub fn fingerprint(&self) -> RsaFingerprint {
        RsaFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Signs a message, returning a 256-byte signature.
    #[frb(sync)]
    pub fn sign(&self, message: Vec<u8>) -> RsaSignature {
        RsaSignature {
            inner: self.inner.sign(&message),
        }
    }
}

/// RsaPublicKey is a 2048-bit RSA public key for verifying digital signatures.
#[frb(opaque)]
pub struct RsaPublicKey {
    pub(crate) inner: darkbio_crypto::rsa::PublicKey,
}

impl RsaPublicKey {
    /// Creates a public key from a 264-byte array.
    /// Format: n (256 bytes) || e (8 bytes).
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 264] = bytes
            .try_into()
            .map_err(|_| "Invalid key length, expected 264 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::rsa::PublicKey::from_bytes(&bytes_array)
                .map_err(|e| e.to_string())?,
        })
    }

    /// Parses a DER-encoded public key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::rsa::PublicKey::from_der(&der).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded public key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::rsa::PublicKey::from_pem(&pem).map_err(|e| e.to_string())?,
        })
    }

    /// Serializes the public key to a 264-byte array.
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

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    #[frb(sync)]
    pub fn fingerprint(&self) -> RsaFingerprint {
        RsaFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Verifies a signature against a message.
    #[frb(sync)]
    pub fn verify(&self, message: Vec<u8>, signature: &RsaSignature) -> Result<(), String> {
        self.inner
            .verify(&message, &signature.inner)
            .map_err(|e| e.to_string())
    }
}

/// RsaSignature is a 256-byte RSA digital signature.
#[frb(opaque)]
pub struct RsaSignature {
    pub(crate) inner: darkbio_crypto::rsa::Signature,
}

impl RsaSignature {
    /// Creates a signature from a 256-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 256] = bytes
            .try_into()
            .map_err(|_| "Invalid signature length, expected 256 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::rsa::Signature::from_bytes(&bytes_array),
        })
    }

    /// Serializes the signature to a 256-byte array.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

/// RsaFingerprint is a 32-byte unique identifier for an RSA key.
#[frb(opaque)]
pub struct RsaFingerprint {
    pub(crate) inner: darkbio_crypto::rsa::Fingerprint,
}

impl RsaFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Invalid fingerprint length, expected 32 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::rsa::Fingerprint::from_bytes(&bytes_array),
        })
    }

    /// Serializes the fingerprint to a 32-byte array.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}
