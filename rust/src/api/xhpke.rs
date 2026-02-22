// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

use flutter_rust_bridge::frb;

use super::xdsa::XdsaPublicKey;

/// XhpkeSecretKey is an X-Wing (X25519 + ML-KEM-768) private key for
/// post-quantum hybrid public-key encryption.
#[frb(opaque)]
pub struct XhpkeSecretKey {
    pub(crate) inner: darkbio_crypto::xhpke::SecretKey,
}

impl XhpkeSecretKey {
    /// Generates a new random private key.
    #[frb(sync)]
    pub fn generate() -> Self {
        Self {
            inner: darkbio_crypto::xhpke::SecretKey::generate(),
        }
    }

    /// Creates a private key from a 32-byte seed.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Invalid key length, expected 32 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xhpke::SecretKey::from_bytes(&bytes_array),
        })
    }

    /// Parses a DER-encoded private key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xhpke::SecretKey::from_der(&der).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded private key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xhpke::SecretKey::from_pem(&pem).map_err(|e| e.to_string())?,
        })
    }

    /// Serializes the private key to a 32-byte seed.
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
    pub fn public_key(&self) -> XhpkePublicKey {
        XhpkePublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    #[frb(sync)]
    pub fn fingerprint(&self) -> XhpkeFingerprint {
        XhpkeFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Creates an HPKE receiver context for multi-message decryption using
    /// the given encapsulated key. Messages must be decrypted in the same
    /// order they were encrypted by the corresponding sender.
    #[frb(sync)]
    pub fn new_receiver(
        &self,
        encap_key: Vec<u8>,
        domain: Vec<u8>,
    ) -> Result<XhpkeReceiver, String> {
        let encap_key_array: [u8; 1120] = encap_key
            .try_into()
            .map_err(|_| "Invalid encapsulated key length, expected 1120 bytes".to_string())?;
        let receiver = self
            .inner
            .new_receiver(&encap_key_array, &domain)
            .map_err(|e| e.to_string())?;
        Ok(XhpkeReceiver { inner: receiver })
    }

    /// Decrypts a message that was encrypted to this key's public counterpart.
    ///
    /// - `session_key`: The 1120-byte encapsulated session key
    /// - `msg_to_open`: The ciphertext to decrypt
    /// - `msg_to_auth`: Additional authenticated data (not encrypted)
    /// - `domain`: Application-specific domain separator
    #[frb(sync)]
    pub fn open(
        &self,
        session_key: Vec<u8>,
        msg_to_open: Vec<u8>,
        msg_to_auth: Vec<u8>,
        domain: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        let session_key_array: [u8; 1120] = session_key
            .try_into()
            .map_err(|_| "Invalid session key length, expected 1120 bytes".to_string())?;
        self.inner
            .open(&session_key_array, &msg_to_open, &msg_to_auth, &domain)
            .map_err(|e| e.to_string())
    }
}

/// XhpkePublicKey is an X-Wing (X25519 + ML-KEM-768) public key for
/// post-quantum hybrid public-key encryption.
#[frb(opaque)]
pub struct XhpkePublicKey {
    pub(crate) inner: darkbio_crypto::xhpke::PublicKey,
}

impl XhpkePublicKey {
    /// Creates a public key from a 1216-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 1216] = bytes
            .try_into()
            .map_err(|_| "Invalid key length, expected 1216 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xhpke::PublicKey::from_bytes(&bytes_array)
                .map_err(|e| e.to_string())?,
        })
    }

    /// Parses a DER-encoded public key.
    #[frb(sync)]
    pub fn from_der(der: Vec<u8>) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xhpke::PublicKey::from_der(&der).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a PEM-encoded public key.
    #[frb(sync)]
    pub fn from_pem(pem: String) -> Result<Self, String> {
        Ok(Self {
            inner: darkbio_crypto::xhpke::PublicKey::from_pem(&pem).map_err(|e| e.to_string())?,
        })
    }

    /// Parses a public key from a DER-encoded certificate, verifying the xDSA signature.
    /// Returns the key along with validity start and end timestamps (Unix seconds).
    #[frb(sync)]
    pub fn from_cert_der(der: Vec<u8>, signer: &XdsaPublicKey) -> Result<(Self, u64, u64), String> {
        let verified = darkbio_crypto::xhpke::verify_cert_der(
            &der,
            &signer.inner,
            darkbio_crypto::x509::ValidityCheck::Disabled,
        )
        .map_err(|e| e.to_string())?;
        Ok((
            Self {
                inner: verified.public_key,
            },
            verified.cert.not_before,
            verified.cert.not_after,
        ))
    }

    /// Parses a public key from a PEM-encoded certificate, verifying the xDSA signature.
    /// Returns the key along with validity start and end timestamps (Unix seconds).
    #[frb(sync)]
    pub fn from_cert_pem(pem: String, signer: &XdsaPublicKey) -> Result<(Self, u64, u64), String> {
        let verified = darkbio_crypto::xhpke::verify_cert_pem(
            &pem,
            &signer.inner,
            darkbio_crypto::x509::ValidityCheck::Disabled,
        )
        .map_err(|e| e.to_string())?;
        Ok((
            Self {
                inner: verified.public_key,
            },
            verified.cert.not_before,
            verified.cert.not_after,
        ))
    }

    /// Serializes the public key to a 1216-byte array.
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
        let template = darkbio_crypto::x509::Certificate {
            subject: darkbio_crypto::x509::Name::new().cn(subject_name),
            issuer: darkbio_crypto::x509::Name::new().cn(issuer_name),
            not_before,
            not_after,
            role: if is_ca {
                darkbio_crypto::x509::Role::Authority { path_len }
            } else {
                darkbio_crypto::x509::Role::Leaf
            },
            extensions: Vec::new(),
        };
        darkbio_crypto::xhpke::issue_cert_der(&self.inner, &signer.inner, &template)
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
        let template = darkbio_crypto::x509::Certificate {
            subject: darkbio_crypto::x509::Name::new().cn(subject_name),
            issuer: darkbio_crypto::x509::Name::new().cn(issuer_name),
            not_before,
            not_after,
            role: if is_ca {
                darkbio_crypto::x509::Role::Authority { path_len }
            } else {
                darkbio_crypto::x509::Role::Leaf
            },
            extensions: Vec::new(),
        };
        darkbio_crypto::xhpke::issue_cert_pem(&self.inner, &signer.inner, &template)
            .map_err(|e| e.to_string())
    }

    /// Returns a 32-byte fingerprint uniquely identifying this key.
    #[frb(sync)]
    pub fn fingerprint(&self) -> XhpkeFingerprint {
        XhpkeFingerprint {
            inner: self.inner.fingerprint(),
        }
    }

    /// Creates an HPKE sender context for multi-message encryption to this
    /// public key. Returns the sender context and the 1120-byte encapsulated
    /// key that must be transmitted to the recipient.
    ///
    /// Messages encrypted with the returned context must be decrypted in order
    /// by the corresponding receiver context.
    #[frb(sync)]
    pub fn new_sender(&self, domain: Vec<u8>) -> Result<(XhpkeSender, Vec<u8>), String> {
        let (sender, encap_key) = self.inner.new_sender(&domain).map_err(|e| e.to_string())?;
        Ok((XhpkeSender { inner: sender }, encap_key.to_vec()))
    }

    /// Encrypts a message to this public key.
    ///
    /// Returns a tuple of (1120-byte session key, ciphertext).
    ///
    /// - `msg_to_seal`: The plaintext to encrypt
    /// - `msg_to_auth`: Additional authenticated data (not encrypted)
    /// - `domain`: Application-specific domain separator
    #[frb(sync)]
    pub fn seal(
        &self,
        msg_to_seal: Vec<u8>,
        msg_to_auth: Vec<u8>,
        domain: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (session_key, ciphertext) = self
            .inner
            .seal(&msg_to_seal, &msg_to_auth, &domain)
            .map_err(|e| e.to_string())?;
        Ok((session_key.to_vec(), ciphertext))
    }
}

/// XhpkeSender wraps an HPKE sender encryption context for multi-message
/// communication. Each call to `seal` encrypts a message using an
/// auto-incrementing nonce, ensuring unique ciphertexts even for identical
/// plaintexts.
///
/// The corresponding `XhpkeReceiver` must process messages in the same order
/// they were sealed.
#[frb(opaque)]
pub struct XhpkeSender {
    inner: darkbio_crypto::xhpke::Sender,
}

impl XhpkeSender {
    /// Encrypts a message using the next nonce in the sequence.
    #[frb(sync)]
    pub fn seal(&mut self, msg_to_seal: Vec<u8>, msg_to_auth: Vec<u8>) -> Result<Vec<u8>, String> {
        self.inner
            .seal(&msg_to_seal, &msg_to_auth)
            .map_err(|e| e.to_string())
    }
}

/// XhpkeReceiver wraps an HPKE receiver decryption context for multi-message
/// communication. Each call to `open` decrypts a message using an
/// auto-incrementing nonce.
///
/// Messages must be provided in the same order they were sealed by the
/// corresponding `XhpkeSender`.
#[frb(opaque)]
pub struct XhpkeReceiver {
    inner: darkbio_crypto::xhpke::Receiver,
}

impl XhpkeReceiver {
    /// Decrypts a message using the next nonce in the sequence.
    #[frb(sync)]
    pub fn open(&mut self, msg_to_open: Vec<u8>, msg_to_auth: Vec<u8>) -> Result<Vec<u8>, String> {
        self.inner
            .open(&msg_to_open, &msg_to_auth)
            .map_err(|e| e.to_string())
    }
}

/// XhpkeFingerprint is a 32-byte unique identifier for an XHPKE key.
#[frb(opaque)]
pub struct XhpkeFingerprint {
    pub(crate) inner: darkbio_crypto::xhpke::Fingerprint,
}

impl XhpkeFingerprint {
    /// Creates a fingerprint from a 32-byte array.
    #[frb(sync)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        let bytes_array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Invalid fingerprint length, expected 32 bytes".to_string())?;
        Ok(Self {
            inner: darkbio_crypto::xhpke::Fingerprint::from_bytes(&bytes_array),
        })
    }

    /// Serializes the fingerprint to a 32-byte array.
    #[frb(sync)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}
