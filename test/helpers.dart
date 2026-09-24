// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';

/// Decodes a hex string into bytes.
Uint8List hex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);

/// Loads a JSON file of test vectors from test/testdata by its path without
/// the extension, such as `cose/v0.16`.
Map<String, dynamic> fixture(String name) =>
    jsonDecode(File('test/testdata/$name.json').readAsStringSync())
        as Map<String, dynamic>;

/// Matches a call that the native library rejects, with an error message
/// containing [text] if given. A Rust panic surfaces as a `PanicException`
/// instead, so it fails this matcher.
Matcher throwsRejection([String? text]) => throwsA(
  text == null ? isA<String>() : allOf(isA<String>(), contains(text)),
);
