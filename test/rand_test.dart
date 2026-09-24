// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:darkbio_crypto/rand.dart' as rand;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  setUpAll(() => RustLib.init());

  // Tests that the requested number of bytes comes back, fresh each time, and
  // that lengths outside the native range are refused.
  test('bytes', () {
    for (final length in [0, 1, 32, 1024]) {
      expect(rand.bytes(length), hasLength(length), reason: '$length');
    }
    expect(rand.bytes(32), isNot(rand.bytes(32)));

    for (final length in [-1, 1 << 32]) {
      expect(() => rand.bytes(length), throwsArgumentError, reason: '$length');
    }
  });
}
