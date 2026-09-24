// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:darkbio_crypto/argon2.dart' as argon2;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart'
    show PanicException;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

/// Test vectors from Go's x/crypto/argon2 package, shared with crypto-rs.
/// Every case derives 24 bytes from "password" and "somesalt".
const vectors = [
  (
    time: 1,
    memory: 64,
    threads: 1,
    hash: '655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb',
  ),
  (
    time: 2,
    memory: 64,
    threads: 1,
    hash: '068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7',
  ),
  (
    time: 2,
    memory: 64,
    threads: 2,
    hash: '350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362',
  ),
  (
    time: 3,
    memory: 256,
    threads: 2,
    hash: '4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b',
  ),
  (
    time: 4,
    memory: 4096,
    threads: 4,
    hash: '145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a',
  ),
  (
    time: 4,
    memory: 1024,
    threads: 8,
    hash: '8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f',
  ),
  (
    time: 2,
    memory: 64,
    threads: 3,
    hash: '4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079',
  ),
  (
    time: 3,
    memory: 1024,
    threads: 6,
    hash: '1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016',
  ),
];

void main() {
  setUpAll(() => RustLib.init());

  final password = utf8.encode('password');
  final salt = utf8.encode('somesalt');

  // Tests the Argon2id derivation against the shared vectors.
  test('vectors', () {
    for (final (i, v) in vectors.indexed) {
      final key = argon2.key(
        password: password,
        salt: salt,
        time: v.time,
        memory: v.memory,
        threads: v.threads,
        length: 24,
      );
      expect(key, hex(v.hash), reason: '$i');
    }
  });

  // Tests that parameters outside the documented limits are rejected, which
  // the native library does by panicking.
  test('limits', () {
    final cases = <void Function()>[
      () => argon2.key(password: password, salt: salt, time: 0, memory: 64),
      () => argon2.key(password: password, salt: salt, threads: 0, memory: 64),
      () => argon2.key(password: password, salt: salt, threads: 2, memory: 15),
      () => argon2.key(password: password, salt: Uint8List(7), memory: 64),
      () => argon2.key(password: password, salt: salt, memory: 64, length: 3),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsA(isA<PanicException>()), reason: '$i');
    }
  });

  // Tests that parameters outside the native 32-bit range are refused rather
  // than wrapped into other, valid ones.
  test('integer ranges', () {
    final cases = <void Function()>[
      () => argon2.key(
        password: password,
        salt: salt,
        time: (1 << 32) + 1,
        memory: 64,
      ),
      () => argon2.key(password: password, salt: salt, memory: (1 << 32) + 64),
      () => argon2.key(
        password: password,
        salt: salt,
        threads: (1 << 32) + 1,
        memory: 64,
      ),
      () => argon2.key(password: password, salt: salt, time: -1, memory: 64),
      () => argon2.key(password: password, salt: salt, memory: 64, length: -1),
      () => argon2.key(
        password: password,
        salt: salt,
        memory: 64,
        length: 1 << 32,
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsArgumentError, reason: '$i');
    }
  });
}
