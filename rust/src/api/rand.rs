use flutter_rust_bridge::frb;

/// Generates cryptographically secure random bytes.
#[frb(sync)]
pub fn random_bytes(length: usize) -> Vec<u8> {
    darkbio_crypto::rand::generate(length)
}
