// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// Argon2id cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc9106
///
/// Turns a password and a salt into key material, made deliberately slow and
/// memory hungry so guessing passwords is expensive. For stretching a secret
/// that is already random, see the `hkdf` library instead.
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/argon2.dart' as argon2;
/// import 'package:darkbio_crypto/rand.dart' as rand;
///
/// void example() {
///   // Store the salt and the costs to derive the same key again later
///   final salt = rand.bytes(16);
///   final key = argon2.key(
///     password: utf8.encode('password'),
///     salt: salt,
///     time: 3,
///     memory: 64 * 1024,
///     threads: 4,
///   );
///   assert(key.length == 32);
/// }
/// ```
library;

import 'dart:typed_data';

import 'src/generated/api/argon2.dart' as ffi;

/// Derives a key from the password, salt and cost parameters using Argon2id,
/// returning [length] bytes that can be used as a cryptographic key.
///
/// [RFC 9106 Section 4](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)
/// recommends time 1, memory 2 GiB (2 * 1024 * 1024 KiB) and threads 4. Its
/// second recommendation, the defaults here, uses time 3, memory 64 MiB
/// (64 * 1024 KiB) and threads 4. Both use a random 16-byte salt and a 32-byte
/// output.
///
/// [time] is the number of passes and [memory] is the total working memory in
/// KiB. [threads] is Argon2's lane count, an algorithm parameter that changes
/// the derived key; it does not select how many threads run. Store the salt
/// and all cost parameters so the same key can be derived on other devices.
/// The derivation blocks the calling isolate until it finishes.
///
/// Throws if any of these input limits are violated:
///
/// - [time] must be 1 to 2^32 - 1.
/// - [threads] must be 1 to 16777215.
/// - [memory] must be 8 * [threads] to 2^32 - 1 KiB.
/// - [salt] must be 8 to 2^32 - 1 bytes.
/// - [password] must be at most 2^32 - 1 bytes.
/// - [length] must be 4 to 2^32 - 1 bytes.
///
/// Also throws if the working memory cannot be allocated.
Uint8List key({
  required Uint8List password,
  required Uint8List salt,
  int time = 3,
  int memory = 65536,
  int threads = 4,
  int length = 32,
}) {
  _checkUint32(time, 'time');
  _checkUint32(memory, 'memory');
  _checkUint32(threads, 'threads');
  _checkUint32(length, 'length');
  return ffi.argon2Key(
    password: password,
    salt: salt,
    time: time,
    memory: memory,
    threads: threads,
    keyLength: BigInt.from(length),
  );
}

/// Rejects a parameter outside the native 32-bit range.
void _checkUint32(int value, String name) {
  if (value < 0 || value > 0xffffffff) {
    throw ArgumentError.value(value, name, 'must be 0 to 2^32 - 1');
  }
}
