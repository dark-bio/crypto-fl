// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart' show CborList, CborSmallInt;
import 'package:darkbio_crypto/cose.dart' as cose;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:darkbio_crypto/xdsa.dart' as xdsa;
import 'package:darkbio_crypto/xhpke.dart' as xhpke;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  setUpAll(() => RustLib.init());

  final domain = utf8.encode('domain');

  // Tests that an embedded signature verifies only under the same key,
  // authenticated message and domain, and hands back its payload.
  test('sign and verify', () {
    final signer = xdsa.SecretKey.generate();
    final signed = cose.sign(
      msgToEmbed: 'payload',
      msgToAuth: 'context',
      signer: signer,
      domain: domain,
    );
    final payload = cose.verify<String>(
      msgToCheck: signed,
      msgToAuth: 'context',
      verifier: signer.publicKey(),
      domain: domain,
      maxDriftSecs: 60,
    );
    expect(payload, 'payload');
    expect(cose.peek<String>(signature: signed), 'payload');
    expect(cose.signer(signature: signed), signer.fingerprint());

    final cases = <void Function()>[
      () => cose.verify<String>(
        msgToCheck: signed,
        msgToAuth: 'other',
        verifier: signer.publicKey(),
        domain: domain,
      ),
      () => cose.verify<String>(
        msgToCheck: signed,
        msgToAuth: 'context',
        verifier: signer.publicKey(),
        domain: utf8.encode('other'),
      ),
      () => cose.verify<String>(
        msgToCheck: signed,
        msgToAuth: 'context',
        verifier: xdsa.SecretKey.generate().publicKey(),
        domain: domain,
      ),
      () => cose.verifyDetached(
        msgToCheck: signed,
        msgToAuth: 'context',
        verifier: signer.publicKey(),
        domain: domain,
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that a detached signature verifies only against the same message,
  // and is refused where an embedded payload is expected.
  test('detached signatures', () {
    final signer = xdsa.SecretKey.generate();
    final signed = cose.signDetached(
      msgToAuth: 'payload',
      signer: signer,
      domain: domain,
    );
    cose.verifyDetached(
      msgToCheck: signed,
      msgToAuth: 'payload',
      verifier: signer.publicKey(),
      domain: domain,
      maxDriftSecs: 60,
    );
    final cases = <void Function()>[
      () => cose.verifyDetached(
        msgToCheck: signed,
        msgToAuth: 'other',
        verifier: signer.publicKey(),
        domain: domain,
      ),
      () => cose.verify<String>(
        msgToCheck: signed,
        msgToAuth: 'payload',
        verifier: signer.publicKey(),
        domain: domain,
      ),
      () => cose.peek<String>(signature: signed),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that a sealed message opens only for its recipient and sender, and
  // that its inner signature can be decrypted and re-encrypted to another
  // recipient.
  test('seal and open', () {
    final signer = xdsa.SecretKey.generate();
    final recipient = xhpke.SecretKey.generate();
    final sealed = cose.seal(
      msgToSeal: 'secret',
      msgToAuth: 'context',
      signer: signer,
      recipient: recipient.publicKey(),
      domain: domain,
    );
    final opened = cose.open<String>(
      msgToOpen: sealed,
      msgToAuth: 'context',
      recipient: recipient,
      sender: signer.publicKey(),
      domain: domain,
      maxDriftSecs: 60,
    );
    expect(opened, 'secret');
    expect(cose.recipient(ciphertext: sealed), recipient.fingerprint());

    final sign1 = cose.decrypt(
      msgToOpen: sealed,
      msgToAuth: 'context',
      recipient: recipient,
      domain: domain,
    );
    final other = xhpke.SecretKey.generate();
    final resealed = cose.encrypt(
      sign1: sign1,
      msgToAuth: 'context',
      recipient: other.publicKey(),
      domain: domain,
    );
    final reopened = cose.open<String>(
      msgToOpen: resealed,
      msgToAuth: 'context',
      recipient: other,
      sender: signer.publicKey(),
      domain: domain,
    );
    expect(reopened, 'secret');

    final cases = <void Function()>[
      () => cose.open<String>(
        msgToOpen: sealed,
        msgToAuth: 'context',
        recipient: other,
        sender: signer.publicKey(),
        domain: domain,
      ),
      () => cose.open<String>(
        msgToOpen: sealed,
        msgToAuth: 'other',
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
      ),
      () => cose.open<String>(
        msgToOpen: sealed,
        msgToAuth: 'context',
        recipient: recipient,
        sender: xdsa.SecretKey.generate().publicKey(),
        domain: domain,
      ),
      () => cose.open<String>(
        msgToOpen: sealed,
        msgToAuth: 'context',
        recipient: recipient,
        sender: signer.publicKey(),
        domain: utf8.encode('other'),
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that payloads round trip through the cbor package, with byte
  // strings coming back as plain integer lists.
  test('payload types', () {
    final signer = xdsa.SecretKey.generate();
    final payload = {
      1: 'text',
      2: Uint8List.fromList([1, 2, 3]),
      3: [true, null, -5],
    };
    final signed = cose.sign(
      msgToEmbed: payload,
      msgToAuth: null,
      signer: signer,
      domain: domain,
    );
    final decoded = cose.verify<Map>(
      msgToCheck: signed,
      msgToAuth: null,
      verifier: signer.publicKey(),
      domain: domain,
    );
    expect(decoded[1], 'text');
    expect(decoded[2], isA<List<int>>());
    expect(decoded[2], [1, 2, 3]);
    expect(decoded[3], [true, null, -5]);
  });

  // Tests that values outside the supported CBOR subset are refused rather
  // than signed.
  test('unsupported payloads', () {
    final signer = xdsa.SecretKey.generate();
    final cases = <Object?>[
      1.5,
      DateTime.utc(2026),
      {2: 'b', 1: 'a'},
      {'key': 'value'},
      CborList([CborSmallInt(-2), CborSmallInt(1)], tags: [4]),
    ];
    for (final (i, value) in cases.indexed) {
      expect(
        () => cose.sign(
          msgToEmbed: value,
          msgToAuth: null,
          signer: signer,
          domain: domain,
        ),
        throwsRejection(),
        reason: '$i',
      );
    }
  });

  // Tests that text holding a lone surrogate is refused rather than signed as
  // U+FFFD, while a surrogate pair signs and reads back intact.
  test('lone surrogates', () {
    final signer = xdsa.SecretKey.generate();
    final cases = <Object?>[
      '\uD800',
      '\uDC00',
      'a\uDC00\uD800b',
      ['\uD800x'],
      {1: '\uD800'},
    ];
    for (final (i, value) in cases.indexed) {
      expect(
        () => cose.sign(
          msgToEmbed: value,
          msgToAuth: null,
          signer: signer,
          domain: domain,
        ),
        throwsArgumentError,
        reason: '$i',
      );
    }
    final signed = cose.sign(
      msgToEmbed: '\u{1F600}',
      msgToAuth: null,
      signer: signer,
      domain: domain,
    );
    final payload = cose.verify<String>(
      msgToCheck: signed,
      msgToAuth: null,
      verifier: signer.publicKey(),
      domain: domain,
    );
    expect(payload, '\u{1F600}');
  });

  // Tests that the v0.16 fixture corpus still validates, since that was in the
  // first public release of the Ark, so the format cannot change anymore.
  test('v0.16 fixtures', () {
    final fx = fixture('cose/v0.16');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final recipient = xhpke.SecretKey.fromBytes(
      hex(fx['xhpke_seed'] as String),
    );
    final domain = hex(fx['domain'] as String);
    final payload = hex(fx['payload'] as String);
    final aad = hex(fx['aad'] as String);
    final sign1 = hex(fx['sign1'] as String);
    final encrypt0 = hex(fx['encrypt0'] as String);

    final verified = cose.verify<List<int>>(
      msgToCheck: sign1,
      msgToAuth: aad,
      verifier: signer.publicKey(),
      domain: domain,
    );
    expect(verified, payload);
    expect(
      () => cose.verify<List<int>>(
        msgToCheck: sign1,
        msgToAuth: aad,
        verifier: signer.publicKey(),
        domain: utf8.encode('wrong'),
      ),
      throwsRejection(),
    );
    final tamperedSign1 = Uint8List.fromList(sign1)..[sign1.length - 1] ^= 1;
    expect(
      () => cose.verify<List<int>>(
        msgToCheck: tamperedSign1,
        msgToAuth: aad,
        verifier: signer.publicKey(),
        domain: domain,
      ),
      throwsRejection(),
    );

    final opened = cose.open<List<int>>(
      msgToOpen: encrypt0,
      msgToAuth: aad,
      recipient: recipient,
      sender: signer.publicKey(),
      domain: domain,
    );
    expect(opened, payload);
    final tamperedEncrypt0 = Uint8List.fromList(encrypt0)
      ..[encrypt0.length - 1] ^= 1;
    expect(
      () => cose.open<List<int>>(
        msgToOpen: tamperedEncrypt0,
        msgToAuth: aad,
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
      ),
      throwsRejection(),
    );
  });

  // Tests that the signature timestamp is held against the allowed drift,
  // using the fixture signature made at a known time in the past.
  test('timestamp drift', () {
    final fx = fixture('cose/v0.16');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final domain = hex(fx['domain'] as String);
    final aad = hex(fx['aad'] as String);
    final sign1 = hex(fx['sign1'] as String);

    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final age = now - (fx['timestamp'] as int);
    List<int> verify(int drift) => cose.verify<List<int>>(
      msgToCheck: sign1,
      msgToAuth: aad,
      verifier: signer.publicKey(),
      domain: domain,
      maxDriftSecs: drift,
    );
    verify(age + 3600);
    expect(() => verify(age - 3600), throwsRejection());
  });

  // Tests that a negative drift is refused by every checking call, instead of
  // passing any timestamp.
  test('negative drift', () {
    final signer = xdsa.SecretKey.generate();
    final recipient = xhpke.SecretKey.generate();
    final signed = cose.sign(
      msgToEmbed: 'payload',
      msgToAuth: null,
      signer: signer,
      domain: domain,
    );
    final detached = cose.signDetached(
      msgToAuth: 'payload',
      signer: signer,
      domain: domain,
    );
    final sealed = cose.seal(
      msgToSeal: 'payload',
      msgToAuth: null,
      signer: signer,
      recipient: recipient.publicKey(),
      domain: domain,
    );
    final cases = <void Function()>[
      () => cose.verify<String>(
        msgToCheck: signed,
        msgToAuth: null,
        verifier: signer.publicKey(),
        domain: domain,
        maxDriftSecs: -1,
      ),
      () => cose.verifyDetached(
        msgToCheck: detached,
        msgToAuth: 'payload',
        verifier: signer.publicKey(),
        domain: domain,
        maxDriftSecs: -1,
      ),
      () => cose.open<String>(
        msgToOpen: sealed,
        msgToAuth: null,
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
        maxDriftSecs: -1,
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsArgumentError, reason: '$i');
    }
  });

  // Tests that lists and maps sign and verify at every length encoding width,
  // as payloads and as authenticated messages.
  test('large collections', () {
    final signer = xdsa.SecretKey.generate();
    for (final size in [255, 256, 65536]) {
      final list = List.generate(size, (i) => i);
      final map = {for (var i = 0; i < size; i++) i: i};
      final signed = cose.sign(
        msgToEmbed: [list, map],
        msgToAuth: list,
        signer: signer,
        domain: domain,
      );
      final payload = cose.verify<List>(
        msgToCheck: signed,
        msgToAuth: list,
        verifier: signer.publicKey(),
        domain: domain,
      );
      expect(payload, [list, map], reason: '$size');
    }
  });

  // Tests against envelopes that crypto-rs made over 300 entry lists, as the
  // payload and as the authenticated message. They open only if both ends
  // encode such lists the same way.
  test('collection fixtures', () {
    final fx = fixture('cose/collections');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final recipient = xhpke.SecretKey.fromBytes(
      hex(fx['xhpke_seed'] as String),
    );
    final domain = hex(fx['domain'] as String);
    final aad = List.generate(300, (i) => i);
    final payload = List.generate(300, (i) => i * 1000);

    final verified = cose.verify<List>(
      msgToCheck: hex(fx['sign1'] as String),
      msgToAuth: aad,
      verifier: signer.publicKey(),
      domain: domain,
    );
    expect(verified, payload);

    final opened = cose.open<List>(
      msgToOpen: hex(fx['encrypt0'] as String),
      msgToAuth: aad,
      recipient: recipient,
      sender: signer.publicKey(),
      domain: domain,
    );
    expect(opened, payload);
  });

  // Tests that a validly signed payload outside the supported CBOR subset, a
  // map with a text key, is refused wherever it would be decoded.
  test('noncanonical payloads', () {
    final fx = fixture('cose/noncanonical');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final recipient = xhpke.SecretKey.fromBytes(
      hex(fx['xhpke_seed'] as String),
    );
    final domain = hex(fx['domain'] as String);
    final sign1 = hex(fx['sign1'] as String);
    final encrypt0 = hex(fx['encrypt0'] as String);

    final cases = <void Function()>[
      () => cose.verify<Object?>(
        msgToCheck: sign1,
        msgToAuth: null,
        verifier: signer.publicKey(),
        domain: domain,
      ),
      () => cose.peek<Object?>(signature: sign1),
      () => cose.open<Object?>(
        msgToOpen: encrypt0,
        msgToAuth: null,
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });
}
