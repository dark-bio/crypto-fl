// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//! Composite ML-DSA-65 and Ed25519 signatures for the Dart bindings.

use flutter_rust_bridge::frb;
use zeroize::Zeroizing;

/// A composite ML-DSA-65 and Ed25519 private key for post-quantum digital
/// signatures.
#[frb(opaque)]
pub struct XdsaSecretKey {
    /// Wrapped upstream xDSA secret key.
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
        let bytes = Zeroizing::new(bytes);
        let seed = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid key length, expected 64 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xdsa::SecretKey::from_bytes(seed),
        })
    }

    /// Parses a DER-encoded private key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xdsa::SecretKey::from_der(&Zeroizing::new(der))
                .map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded private key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xdsa::SecretKey::from_pem(&Zeroizing::new(pem))
                .map_err(|e| e.to_string())?,
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
        self.inner.to_der().to_vec()
    }

    /// Serializes the private key to PEM format.
    #[frb(sync)]
    pub fn to_pem(&self) -> String {
        self.inner.to_pem().to_string()
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

    /// Signs a message with hedged ML-DSA-65 and Ed25519.
    #[frb(sync)]
    pub fn sign(&self, message: Vec<u8>) -> XdsaSignature {
        XdsaSignature {
            inner: self.inner.sign(&message),
        }
    }
}

/// A composite ML-DSA-65 and Ed25519 public key for verifying post-quantum
/// digital signatures.
#[frb(opaque)]
pub struct XdsaPublicKey {
    /// Wrapped upstream xDSA public key.
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

/// A composite ML-DSA-65 and Ed25519 digital signature.
#[frb(opaque)]
pub struct XdsaSignature {
    /// Wrapped upstream xDSA signature.
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

/// A 32-byte unique identifier for an xDSA key.
#[frb(opaque)]
pub struct XdsaFingerprint {
    /// Wrapped upstream xDSA fingerprint.
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
