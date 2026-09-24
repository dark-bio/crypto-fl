// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Streaming authenticated encryption based on age's STREAM construction.
///
/// https://eprint.iacr.org/2015/189.pdf
///
/// Plaintext is split into 64 KiB chunks, each sealed with ChaCha20-Poly1305
/// under a nonce that counts up and marks the final chunk, so truncation and
/// reordering are detected. Both functions take and return whole buffers.
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/rand.dart' as rand;
/// import 'package:darkbio_crypto/stream.dart' as stream;
///
/// void example() {
///   // Never reuse a key across streams
///   final key = rand.bytes(32);
///
///   final ciphertext = stream.encrypt(key: key, plaintext: utf8.encode('hello stream'));
///   final plaintext = stream.decrypt(key: key, ciphertext: ciphertext);
///   assert(utf8.decode(plaintext) == 'hello stream');
/// }
/// ```
library;

import 'dart:typed_data';

import 'src/generated/api/stream.dart' as ffi;

/// Encrypts [plaintext] as a STREAM under the 32-byte [key].
///
/// The key must **never** be repeated across multiple streams. Derive it with
/// HKDF from both a random file key and a random nonce.
///
/// Throws if [key] is not 32 bytes long.
Uint8List encrypt({required Uint8List key, required Uint8List plaintext}) =>
    ffi.streamEncrypt(key: key, plaintext: plaintext);

/// Decrypts a STREAM [ciphertext] under the 32-byte [key] it was encrypted
/// with.
///
/// Throws if [key] is not 32 bytes long, or if the ciphertext does not
/// authenticate under it, such as when it was truncated, reordered or
/// tampered with.
Uint8List decrypt({required Uint8List key, required Uint8List ciphertext}) =>
    ffi.streamDecrypt(key: key, ciphertext: ciphertext);
