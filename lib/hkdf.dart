// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// HKDF-SHA256 key derivation.
///
/// https://datatracker.ietf.org/doc/html/rfc5869
///
/// Derives context-specific keys from a high-entropy secret such as a shared
/// secret or a file key. For password-based key derivation, see the `argon2`
/// library.
///
/// ```dart
/// import 'dart:convert';
/// import 'dart:typed_data';
///
/// import 'package:darkbio_crypto/hkdf.dart' as hkdf;
/// import 'package:darkbio_crypto/rand.dart' as rand;
///
/// (Uint8List, Uint8List) example() {
///   final secret = rand.bytes(32);
///   final salt = Uint8List(0);
///
///   // Distinct contexts derive independent keys from the same secret
///   final encryption = hkdf.key(secret: secret, salt: salt, info: utf8.encode('example encryption key'));
///   final authentication = hkdf.key(secret: secret, salt: salt, info: utf8.encode('example authentication key'));
///   return (encryption, authentication);
/// }
/// ```
library;

import 'dart:typed_data';

import 'src/generated/api/hkdf.dart' as ffi;

/// Derives a [length]-byte key from [secret], [salt] and [info] using
/// HKDF-SHA256.
///
/// Pass an empty [salt] when none is needed.
///
/// Throws if [length] is negative or exceeds 8160 bytes (255 * 32).
Uint8List key({
  required Uint8List secret,
  required Uint8List salt,
  required Uint8List info,
  int length = 32,
}) {
  _checkLength(length);
  return ffi.hkdfKey(
    secret: secret,
    salt: salt,
    info: info,
    length: BigInt.from(length),
  );
}

/// Extracts a 32-byte pseudorandom key from [secret] and [salt], for use with
/// [expand].
///
/// Reuse the extracted key with [expand] to derive keys for different
/// contexts. [key] performs both steps in one call. Pass an empty [salt] when
/// none is needed.
Uint8List extract({required Uint8List secret, required Uint8List salt}) =>
    ffi.hkdfExtract(secret: secret, salt: salt);

/// Derives a [length]-byte key from a 32-byte pseudorandom key [prk] and
/// context [info], skipping the extraction step.
///
/// [prk] should come from [extract], or be a uniformly random or pseudorandom
/// cryptographically strong key (RFC 5869 Section 3.3). Most callers should
/// use [key] instead.
///
/// Throws if [prk] is not 32 bytes long, or if [length] is negative or exceeds
/// 8160 bytes (255 * 32).
Uint8List expand({
  required Uint8List prk,
  required Uint8List info,
  int length = 32,
}) {
  _checkLength(length);
  return ffi.hkdfExpand(prk: prk, info: info, length: BigInt.from(length));
}

/// Rejects an output length beyond what SHA-256 HKDF can produce.
void _checkLength(int length) {
  if (length < 0 || length > 8160) {
    throw ArgumentError.value(length, 'length', 'must be 0 to 8160');
  }
}
