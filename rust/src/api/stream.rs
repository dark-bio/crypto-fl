use flutter_rust_bridge::frb;
use std::io::{Read, Write};

/// Encrypts plaintext using the STREAM construction with ChaCha20-Poly1305.
/// The key must be exactly 32 bytes and should never be reused across streams.
#[frb(sync)]
pub fn stream_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let key_array: [u8; 32] = key
        .try_into()
        .map_err(|_| "Invalid key length, expected 32 bytes".to_string())?;

    let payload_key = darkbio_crypto::stream::PayloadKey(key_array.into());

    let mut ciphertext = Vec::new();
    let mut writer = darkbio_crypto::stream::Stream::encrypt(payload_key, &mut ciphertext);

    writer
        .write_all(&plaintext)
        .map_err(|e| format!("Encryption write error: {}", e))?;

    writer
        .finish()
        .map_err(|e| format!("Encryption finish error: {}", e))?;

    Ok(ciphertext)
}

/// Decrypts ciphertext using the STREAM construction with ChaCha20-Poly1305.
/// The key must be exactly 32 bytes and must match the key used for encryption.
#[frb(sync)]
pub fn stream_decrypt(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, String> {
    let key_array: [u8; 32] = key
        .try_into()
        .map_err(|_| "Invalid key length, expected 32 bytes".to_string())?;

    let payload_key = darkbio_crypto::stream::PayloadKey(key_array.into());

    let mut reader = darkbio_crypto::stream::Stream::decrypt(payload_key, ciphertext.as_slice());

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| format!("Decryption error: {}", e))?;

    Ok(plaintext)
}
