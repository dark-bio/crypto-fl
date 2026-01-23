use flutter_rust_bridge::frb;

/// Derives a cryptographic key from a password using Argon2id.
///
/// - `password`: The password to derive the key from
/// - `salt`: The salt (should be random, at least 16 bytes)
/// - `time`: Number of iterations (RFC 9106 recommends 1)
/// - `memory`: Memory size in KiB (RFC 9106 recommends 2048*1024 for 2GB)
/// - `threads`: Degree of parallelism
/// - `key_length`: Desired output key length in bytes
///
/// Returns the derived key of the specified length.
#[frb(sync)]
pub fn argon2_key(
    password: Vec<u8>,
    salt: Vec<u8>,
    time: u32,
    memory: u32,
    threads: u32,
    key_length: usize,
) -> Vec<u8> {
    darkbio_crypto::argon2::key_with_len(&password, &salt, time, memory, threads, key_length)
}
