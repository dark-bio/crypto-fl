// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'package:darkbio_crypto/cbor.dart' as cbor;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  setUpAll(() => RustLib.init());

  // Tests that encodings within the restricted CBOR subset are accepted.
  test('accepts the subset', () {
    final cases = [
      '83016374776f4103', // [1, "two", h'03']
      'a2010203f6', // {1: 2, 3: null}
      'a201002000', // {1: 0, -1: 0}
      '3903e7', // -1000
      'f5', // true
      'f6', // null
    ];
    for (final (i, input) in cases.indexed) {
      expect(() => cbor.verify(hex(input)), returnsNormally, reason: '$i');
    }
  });

  // Tests that encodings outside the restricted CBOR subset are rejected.
  test('rejects everything else', () {
    final cases = [
      '', // no item
      '0101', // trailing item
      '1817', // 23 in a longer form than needed
      'a202000100', // {2: 0, 1: 0}, keys out of order
      'a201000100', // {1: 0, 1: 0}, duplicate keys
      'a1616101', // {"a": 1}, text key
      'f93c00', // 1.0 as a half float
      'c100', // tag 1 around 0
      '9fff', // indefinite length array
      '6180', // text that is not valid UTF-8
    ];
    for (final (i, input) in cases.indexed) {
      expect(() => cbor.verify(hex(input)), throwsRejection(), reason: '$i');
    }
  });

  // Tests the nesting limit, which admits 31 arrays around an integer but not
  // 32.
  test('nesting limit', () {
    expect(() => cbor.verify(hex('${'81' * 31}00')), returnsNormally);
    expect(() => cbor.verify(hex('${'81' * 32}00')), throwsRejection());
  });
}
