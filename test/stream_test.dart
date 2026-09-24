// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:darkbio_crypto/hkdf.dart' as hkdf;
import 'package:darkbio_crypto/rand.dart' as rand;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:darkbio_crypto/stream.dart' as stream;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

/// Size of a plaintext chunk in bytes.
const chunk = 64 * 1024;

/// Finds the first occurrence of [pattern] in [data], or -1 if absent.
int find(List<int> data, List<int> pattern) {
  outer:
  for (var i = 0; i + pattern.length <= data.length; i++) {
    for (var j = 0; j < pattern.length; j++) {
      if (data[i + j] != pattern[j]) {
        continue outer;
      }
    }
    return i;
  }
  return -1;
}

void main() {
  setUpAll(() => RustLib.init());

  // Tests that plaintexts around the chunk boundaries survive a round trip.
  test('round trip', () {
    final key = rand.bytes(32);
    for (final size in [0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk]) {
      final plaintext = Uint8List.fromList(List.generate(size, (i) => i % 251));
      final ciphertext = stream.encrypt(key: key, plaintext: plaintext);
      expect(
        stream.decrypt(key: key, ciphertext: ciphertext),
        plaintext,
        reason: '$size',
      );
    }
  });

  // Tests that tampering, truncation, trailing data and the wrong key are all
  // detected, and that keys must be 32 bytes.
  test('rejections', () {
    final key = rand.bytes(32);
    final ciphertext = stream.encrypt(
      key: key,
      plaintext: Uint8List(chunk + 100),
    );
    final cases = <void Function()>[
      () => stream.decrypt(
        key: key,
        ciphertext: Uint8List.fromList(ciphertext)..[10] ^= 1,
      ),
      () => stream.decrypt(
        key: key,
        ciphertext: Uint8List.sublistView(ciphertext, 0, chunk + 16),
      ),
      () => stream.decrypt(
        key: key,
        ciphertext: Uint8List.sublistView(ciphertext, 0, ciphertext.length - 1),
      ),
      () => stream.decrypt(
        key: key,
        ciphertext: Uint8List.fromList([...ciphertext, 0]),
      ),
      () => stream.decrypt(key: key, ciphertext: Uint8List(0)),
      () => stream.decrypt(key: rand.bytes(32), ciphertext: ciphertext),
      () => stream.encrypt(key: Uint8List(31), plaintext: Uint8List(1)),
      () => stream.decrypt(key: Uint8List(33), ciphertext: ciphertext),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests against the C2SP CCTV age testkit, stream family, copied from
  // crypto-rs. Success vectors must decrypt and encrypt back into the same
  // ciphertext, and failure vectors must be rejected.
  test('CCTV vectors', () {
    final files = Directory('test/testdata/stream/cctv')
        .listSync()
        .whereType<File>()
        .where((file) => file.uri.pathSegments.last.startsWith('stream_'));
    for (final file in files) {
      final name = file.uri.pathSegments.last;
      final data = file.readAsBytesSync();

      // Split the vector into its textual header and the age file body
      final sep = find(data, [0x0a, 0x0a]);
      final header = <String, String>{
        for (final line in utf8.decode(data.sublist(0, sep)).split('\n'))
          line.substring(0, line.indexOf(': ')): line.substring(
            line.indexOf(': ') + 2,
          ),
      };
      var body = data.sublist(sep + 2);
      if (header['compressed'] == 'zlib') {
        body = Uint8List.fromList(zlib.decode(body));
      }
      // Slice off the age header and its MAC line to reach the payload
      final mac = find(body, utf8.encode('\n--- '));
      final end = mac + 1 + find(body.sublist(mac + 1), [0x0a]);
      final payload = body.sublist(end + 1);

      // A payload too short for its nonce never carries a success vector
      if (payload.length < 16) {
        expect(header['expect'], isNot('success'), reason: name);
        continue;
      }
      final key = hkdf.key(
        secret: hex(header['file key']!),
        salt: payload.sublist(0, 16),
        info: utf8.encode('payload'),
      );
      final ciphertext = payload.sublist(16);
      if (header['expect'] == 'success') {
        final plaintext = stream.decrypt(key: key, ciphertext: ciphertext);
        expect(
          stream.encrypt(key: key, plaintext: plaintext),
          ciphertext,
          reason: name,
        );
      } else {
        expect(
          () => stream.decrypt(key: key, ciphertext: ciphertext),
          throwsRejection(),
          reason: name,
        );
      }
    }
  });
}
