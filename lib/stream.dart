/// I/O helper structs for age file encryption and decryption.
///
/// The [STREAM](https://eprint.iacr.org/2015/189.pdf) construction for online
/// authenticated encryption, instantiated with ChaCha20-Poly1305 in 64KiB
/// chunks, and a nonce structure of 11 bytes of big endian counter, and 1 byte
/// of last block flag (0x00 / 0x01).
library;

import 'dart:typed_data';

import 'src/generated/api/stream.dart' as ffi;

/// Wraps `STREAM` encryption under the given [key].
///
/// [key] must **never** be repeated across multiple streams.
Uint8List encrypt({required Uint8List key, required Uint8List plaintext}) =>
    ffi.streamEncrypt(key: key, plaintext: plaintext);

/// Wraps `STREAM` decryption under the given [key].
///
/// [key] must **never** be repeated across multiple streams.
Uint8List decrypt({required Uint8List key, required Uint8List ciphertext}) =>
    ffi.streamDecrypt(key: key, ciphertext: ciphertext);
