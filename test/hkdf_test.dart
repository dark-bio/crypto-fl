// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:typed_data';

import 'package:darkbio_crypto/hkdf.dart' as hkdf;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

/// Test vectors from RFC 5869 Appendix A, the SHA-256 cases A.1 to A.3.
const vectors = [
  (
    secret: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '000102030405060708090a0b0c',
    info: 'f0f1f2f3f4f5f6f7f8f9',
    prk: '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
    out:
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        '34007208d5b887185865',
  ),
  (
    secret:
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f',
    salt:
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    info:
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    prk: '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
    out:
        'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c'
        '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71'
        'cc30c58179ec3e87c14c01d5c1f3434f1d87',
  ),
  (
    secret: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    salt: '',
    info: '',
    prk: '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
    out:
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
        '9d201395faa4b61a96c8',
  ),
];

void main() {
  setUpAll(() => RustLib.init());

  // Tests the one-step derivation and its extract and expand halves against
  // the RFC vectors.
  test('RFC 5869 vectors', () {
    for (final (i, v) in vectors.indexed) {
      final out = hex(v.out);
      final key = hkdf.key(
        secret: hex(v.secret),
        salt: hex(v.salt),
        info: hex(v.info),
        length: out.length,
      );
      expect(key, out, reason: '$i');

      final prk = hkdf.extract(secret: hex(v.secret), salt: hex(v.salt));
      expect(prk, hex(v.prk), reason: '$i');

      final expanded = hkdf.expand(
        prk: prk,
        info: hex(v.info),
        length: out.length,
      );
      expect(expanded, out, reason: '$i');
    }
  });

  // Tests that the output length range and the key size are enforced.
  test('limits', () {
    final secret = Uint8List(32);
    expect(
      hkdf.key(secret: secret, salt: secret, info: secret, length: 8160),
      hasLength(8160),
    );
    final cases = <(void Function(), Matcher)>[
      (
        () => hkdf.key(secret: secret, salt: secret, info: secret, length: -1),
        throwsArgumentError,
      ),
      (
        () =>
            hkdf.key(secret: secret, salt: secret, info: secret, length: 8161),
        throwsArgumentError,
      ),
      (
        () => hkdf.expand(prk: secret, info: secret, length: 8161),
        throwsArgumentError,
      ),
      (() => hkdf.expand(prk: Uint8List(31), info: secret), throwsRejection()),
    ];
    for (final (i, (run, matcher)) in cases.indexed) {
      expect(run, matcher, reason: '$i');
    }
  });
}
