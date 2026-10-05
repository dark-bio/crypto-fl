// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart' show CborList, CborSmallInt;
import 'package:cbor/simple.dart' as cbor;
import 'package:darkbio_crypto/cose.dart' as cose;
import 'package:darkbio_crypto/src/encoding.dart' as encoding;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:darkbio_crypto/xdsa.dart' as xdsa;
import 'package:darkbio_crypto/xhpke.dart' as xhpke;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

/// Opens the AEAD plaintext directly, preserving padding for wire assertions.
Uint8List _openPlaintext(
  Uint8List envelope,
  Object? aad,
  xhpke.SecretKey recipient,
  Uint8List domain,
) {
  final fields = cbor.cbor.decode(envelope) as List;
  final protected = Uint8List.fromList(fields[0] as List<int>);
  final unprotected = fields[1] as Map;
  return recipient.open(
    sessionKey: Uint8List.fromList(unprotected[-4] as List<int>),
    msgToOpen: Uint8List.fromList(fields[2] as List<int>),
    msgToAuth: encoding.encode(['Encrypt0', protected, encoding.encode(aad)]),
    domain: domain,
  );
}

/// Encrypts arbitrary plaintext with the COSE headers to test reader rejection.
Uint8List _sealPlaintext(
  Uint8List plaintext,
  Object? aad,
  xhpke.PublicKey recipient,
  Uint8List domain,
) {
  // Bind the headers and AAD as the wire profile requires
  final protected = encoding.encode({
    1: -70001,
    4: recipient.fingerprint().toBytes(),
  });
  final authenticated = encoding.encode([
    'Encrypt0',
    protected,
    encoding.encode(aad),
  ]);

  // Authenticate the raw plaintext, including any malformed padding
  final (encapKey, ciphertext) = recipient.seal(
    msgToSeal: plaintext,
    msgToAuth: authenticated,
    domain: domain,
  );
  return encoding.encode([
    protected,
    {-4: encapKey},
    ciphertext,
  ]);
}

void main() {
  setUpAll(() => RustLib.init());

  final domain = utf8.encode('domain');

  // Tests the fixed bucket sequences and boundary targets from crypto-rs.
  test('padding bucket sizes', () {
    final recipient = xhpke.SecretKey.fromBytes(
      Uint8List(32)..fillRange(0, 32, 7),
    );
    addTearDown(recipient.dispose);
    int encryptedLength(int length, cose.Padding padding) {
      final envelope = cose.encrypt(
        sign1: Uint8List(length),
        msgToAuth: null,
        recipient: recipient.publicKey(),
        domain: domain,
        padding: padding,
      );
      return _openPlaintext(envelope, null, recipient, domain).length;
    }

    // Check each rounded-up transition against upstream's literal expectations
    final sequences = [
      (
        8192,
        20,
        [8192, 8602, 9033, 9485, 9960, 10458, 10981, 11531, 12108, 12714],
      ),
      (100, 3, [100, 134, 179, 239, 319, 426]),
    ];
    for (final (floor, step, sizes) in sequences) {
      final padding = cose.Padding.buckets(floor: floor, step: step);
      for (var i = 0; i < sizes.length - 1; i++) {
        expect(
          encryptedLength(sizes[i], padding),
          sizes[i],
          reason: '$floor/$step/$i',
        );
        expect(
          encryptedLength(sizes[i] + 1, padding),
          sizes[i + 1],
          reason: '$floor/$step/$i',
        );
      }
    }

    final padding = cose.Padding.buckets(floor: 8192, step: 20);
    for (final (length, expected) in [
      (0, 8192),
      (1, 8192),
      (8192, 8192),
      (8193, 8602),
      (8602, 8602),
      (8603, 9033),
      (300000, 303278),
    ]) {
      expect(encryptedLength(length, padding), expected, reason: '$length');
    }

    for (final length in [0, 1, 8192, 8193, 300000]) {
      expect(
        encryptedLength(length, const cose.Padding.none()),
        length,
        reason: '$length',
      );
    }
    expect(
      encryptedLength(101, cose.Padding.buckets(floor: 100, step: 1)),
      200,
    );
    expect(
      encryptedLength(256, cose.Padding.buckets(floor: 1, step: 0xffffffff)),
      256,
    );
  });

  // Tests every parameter and size error before any policy can reach Rust.
  test('padding prevalidation', () {
    // Include zero and negative values, and values beyond a 32-bit usize
    for (final value in [-1, 0, 0x100000000]) {
      expect(
        () => cose.Padding.buckets(floor: value, step: 20),
        throwsArgumentError,
        reason: 'floor/$value',
      );
      expect(
        () => cose.Padding.buckets(floor: 8192, step: value),
        throwsArgumentError,
        reason: 'step/$value',
      );
    }
    for (final value in [1, 0xffffffff]) {
      expect(
        () => cose.Padding.buckets(floor: value, step: value),
        returnsNormally,
        reason: '$value',
      );
    }
  });

  // Tests both policies against the fixed v0.16 signature and its exact zeros.
  test('sealed plaintext padding', () {
    // Reuse the shared fixture so the expected signature is independent
    final fx = fixture('cose/v0.16');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final recipient = xhpke.SecretKey.fromBytes(
      hex(fx['xhpke_seed'] as String),
    );
    addTearDown(signer.dispose);
    addTearDown(recipient.dispose);
    final domain = hex(fx['domain'] as String);
    final aad = hex(fx['aad'] as String);
    final sign1 = hex(fx['sign1'] as String);
    final payload = utf8.encode('cose fixture payload');

    // Pin both plaintext and outer envelope lengths for sealing and re-encryption
    for (final (padding, plaintextLength, zeros, sealedLength) in [
      (const cose.Padding.none(), 3461, 0, 4650),
      (cose.Padding.buckets(floor: 8192, step: 20), 8192, 4731, 9381),
    ]) {
      final sealed = cose.sealAt(
        msgToSeal: payload,
        msgToAuth: aad,
        signer: signer,
        recipient: recipient.publicKey(),
        domain: domain,
        padding: padding,
        timestamp: 1700000000,
      );
      final encrypted = cose.encrypt(
        sign1: sign1,
        msgToAuth: aad,
        recipient: recipient.publicKey(),
        domain: domain,
        padding: padding,
      );
      for (final (i, envelope) in [sealed, encrypted].indexed) {
        final id = '$plaintextLength/$i';
        expect(envelope.length, sealedLength, reason: id);
        final plaintext = _openPlaintext(envelope, aad, recipient, domain);
        expect(plaintext.length, plaintextLength, reason: id);
        expect(plaintext.sublist(0, 3461), sign1, reason: id);
        expect(plaintext.sublist(3461), Uint8List(zeros), reason: id);
        expect(
          cose.decrypt(
            msgToOpen: envelope,
            msgToAuth: aad,
            recipient: recipient,
            domain: domain,
          ),
          sign1,
          reason: id,
        );
        expect(
          cose.open<List<int>>(
            msgToOpen: envelope,
            msgToAuth: aad,
            recipient: recipient,
            sender: signer.publicKey(),
            domain: domain,
          ),
          payload,
          reason: id,
        );
      }
    }
  });

  test('sealed padding across CBOR widths', () {
    final signer = xdsa.SecretKey.generate();
    final recipient = xhpke.SecretKey.generate();
    addTearDown(signer.dispose);
    addTearDown(recipient.dispose);

    final sizes = [
      8192,
      8602,
      9033,
      9485,
      9960,
      10458,
      10981,
      11531,
      12108,
      12714,
    ];
    for (final (payload, timestamp) in [
      (Uint8List(0), 0),
      (Uint8List(22), 23),
      (Uint8List(23), 24),
      (Uint8List(24), 255),
      (Uint8List(253), 256),
      (Uint8List(254), 65535),
      (Uint8List(255), 65536),
      (Uint8List(256), 0xffffffff),
      (Uint8List(4750), 1700000000),
      (Uint8List(5000), 1700000000),
      (Uint8List(5500), 1700000000),
      (Uint8List(6000), 1700000000),
      (Uint8List(6500), 1700000000),
      (Uint8List(7000), 1700000000),
      (Uint8List(7500), 1700000000),
      (Uint8List(8000), 1700000000),
      (Uint8List(8500), 1700000000),
      (Uint8List(9000), 1700000000),
      (Uint8List(65532), 0x100000000),
      (Uint8List(65533), -1),
      (Uint8List(65535), -25),
      (Uint8List(65536), -9223372036854775808),
      (Uint8List(0), 9223372036854775807),
    ]) {
      final id = '${payload.length}/$timestamp';
      final signed = cose.signAt(
        msgToEmbed: payload,
        msgToAuth: null,
        signer: signer,
        domain: domain,
        timestamp: timestamp,
      );
      final buckets = payload.length < 65532 ? sizes : [100000];
      final expected = buckets.firstWhere((size) => size >= signed.length);
      final padding = cose.Padding.buckets(floor: buckets.first, step: 20);
      final envelope = cose.sealAt(
        msgToSeal: payload,
        msgToAuth: null,
        signer: signer,
        recipient: recipient.publicKey(),
        domain: domain,
        padding: padding,
        timestamp: timestamp,
      );
      final plaintext = _openPlaintext(envelope, null, recipient, domain);
      expect(plaintext.length, expected, reason: id);
      expect(plaintext.sublist(0, signed.length), signed, reason: id);
      expect(plaintext.sublist(signed.length), everyElement(0), reason: id);
      expect(
        cose.openAt<List<int>>(
          msgToOpen: envelope,
          msgToAuth: null,
          recipient: recipient,
          sender: signer.publicKey(),
          domain: domain,
          maxDriftSecs: 0,
          now: timestamp,
        ),
        payload,
        reason: id,
      );
    }
  });

  // Tests acceptance of off-bucket zeros and rejection of authenticated nonzeros.
  test('decrypted padding validation', () {
    // Append 37 zeros to the shared 3461-byte signature, matching crypto-rs
    final fx = fixture('cose/v0.16');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final recipient = xhpke.SecretKey.fromBytes(
      Uint8List(32)..fillRange(0, 32, 7),
    );
    addTearDown(signer.dispose);
    addTearDown(recipient.dispose);
    final domain = hex(fx['domain'] as String);
    final aad = hex(fx['aad'] as String);
    final sign1 = hex(fx['sign1'] as String);
    final plaintext = Uint8List(3498)..setAll(0, sign1);
    final envelope = _sealPlaintext(
      plaintext,
      aad,
      recipient.publicKey(),
      domain,
    );
    expect(
      cose.decrypt(
        msgToOpen: envelope,
        msgToAuth: aad,
        recipient: recipient,
        domain: domain,
      ),
      sign1,
    );
    expect(
      cose.openAt<List<int>>(
        msgToOpen: envelope,
        msgToAuth: aad,
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
        maxDriftSecs: 0,
        now: 1700000000,
      ),
      utf8.encode('cose fixture payload'),
    );

    // Corrupt the start, middle and end while keeping the encryption authentic
    for (final position in [3461, 3479, 3497]) {
      for (final byte in [1, 255]) {
        plaintext[position] = byte;
        final envelope = _sealPlaintext(
          plaintext,
          aad,
          recipient.publicKey(),
          domain,
        );
        final checks = <void Function()>[
          () => cose.decrypt(
            msgToOpen: envelope,
            msgToAuth: aad,
            recipient: recipient,
            domain: domain,
          ),
          () => cose.open<List<int>>(
            msgToOpen: envelope,
            msgToAuth: aad,
            recipient: recipient,
            sender: signer.publicKey(),
            domain: domain,
          ),
          () => cose.openAt<List<int>>(
            msgToOpen: envelope,
            msgToAuth: aad,
            recipient: recipient,
            sender: signer.publicKey(),
            domain: domain,
            now: 1700000000,
          ),
        ];
        for (final (i, check) in checks.indexed) {
          expect(
            check,
            throwsRejection('invalid padding'),
            reason: '$position/$byte/$i',
          );
        }
        plaintext[position] = 0;
      }
    }
  });

  // Tests that malformed CBOR is refused before decrypt returns a signed item.
  test('decrypt rejects malformed plaintext', () {
    final recipient = xhpke.SecretKey.fromBytes(
      Uint8List(32)..fillRange(0, 32, 7),
    );
    addTearDown(recipient.dispose);
    final cases = [
      <int>[],
      [0x82, 0],
      [0x81, 0x42, 0],
      [0x18, 0],
      [0xc0, 0],
      [0x9f, 0xff],
      [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
      [...List.filled(32, 0x81), 0],
    ];
    for (final (i, plaintext) in cases.indexed) {
      final envelope = _sealPlaintext(
        Uint8List.fromList(plaintext),
        null,
        recipient.publicKey(),
        domain,
      );
      expect(
        () => cose.decrypt(
          msgToOpen: envelope,
          msgToAuth: null,
          recipient: recipient,
          domain: domain,
        ),
        throwsRejection(),
        reason: '$i',
      );
    }
  });

  // Tests that stripping preserves the original CBOR item, including its zeros.
  test('decrypt preserves CBOR item', () {
    final recipient = xhpke.SecretKey.fromBytes(
      Uint8List(32)..fillRange(0, 32, 7),
    );
    addTearDown(recipient.dispose);
    final plaintext = Uint8List.fromList([
      0x82,
      0xa2,
      2,
      0,
      1,
      0,
      0x43,
      0,
      1,
      0,
      0,
      0,
      0,
    ]);
    final envelope = _sealPlaintext(
      plaintext,
      null,
      recipient.publicKey(),
      domain,
    );
    expect(
      cose.decrypt(
        msgToOpen: envelope,
        msgToAuth: null,
        recipient: recipient,
        domain: domain,
      ),
      [0x82, 0xa2, 2, 0, 1, 0, 0x43, 0, 1, 0],
    );
  });

  // Tests the padded fixture generated once by crypto-rs from invented data.
  test('padded fixture', () {
    final fx = fixture('cose/padded');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final recipient = xhpke.SecretKey.fromBytes(
      hex(fx['xhpke_seed'] as String),
    );
    addTearDown(signer.dispose);
    addTearDown(recipient.dispose);
    final domain = hex(fx['domain'] as String);
    final aad = hex(fx['aad'] as String);
    final sign1 = hex(fx['sign1'] as String);
    final envelope = hex(fx['encrypt0'] as String);

    // Pin the exact plaintext layout independently of the sender implementation
    expect(fx['padding'], {'type': 'buckets', 'floor': 8192, 'step': 20});
    expect(fx['plaintext_length'], 8192);
    final plaintext = _openPlaintext(envelope, aad, recipient, domain);
    expect(plaintext.length, 8192);
    expect(plaintext.sublist(0, 3470), sign1);
    expect(plaintext.sublist(3470), Uint8List(4722));
    expect(
      cose.decrypt(
        msgToOpen: envelope,
        msgToAuth: aad,
        recipient: recipient,
        domain: domain,
      ),
      sign1,
    );

    // Verify the fixed timestamp and payload through the unchanged opening API
    expect(fx['timestamp'], 1700000000);
    final payload = cose.openAt<List<int>>(
      msgToOpen: envelope,
      msgToAuth: aad,
      recipient: recipient,
      sender: signer.publicKey(),
      domain: domain,
      maxDriftSecs: 0,
      now: 1700000000,
    );
    expect(payload, utf8.encode('padded cose fixture payload'));
    expect(payload, hex(fx['payload'] as String));
  });

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
      padding: cose.Padding.buckets(floor: 8192, step: 20),
    );
    expect(sealed.length, 9381);
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
      padding: const cose.Padding.none(),
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
  // strings coming back as plain integer lists. The largest 64-bit integer
  // only fits a BigInt, yet still encodes as a plain CBOR integer.
  test('payload types', () {
    final signer = xdsa.SecretKey.generate();
    final payload = {
      1: 'text',
      2: Uint8List.fromList([1, 2, 3]),
      3: [true, null, -5],
      4: BigInt.two.pow(64) - BigInt.one,
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
    expect(decoded[4], BigInt.two.pow(64) - BigInt.one);
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

  // Tests that the drift is measured against the time the caller gives, at
  // both edges of the allowed window, using the fixtures made at a known time.
  test('drift against a given time', () {
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
    final timestamp = fx['timestamp'] as int;

    List<int> verify(int now) => cose.verifyAt<List<int>>(
      msgToCheck: sign1,
      msgToAuth: aad,
      verifier: signer.publicKey(),
      domain: domain,
      maxDriftSecs: 60,
      now: now,
    );
    List<int> open(int now) => cose.openAt<List<int>>(
      msgToOpen: encrypt0,
      msgToAuth: aad,
      recipient: recipient,
      sender: signer.publicKey(),
      domain: domain,
      maxDriftSecs: 60,
      now: now,
    );
    final cases = [
      (timestamp + 60, true), // a signature 60 s old
      (timestamp - 60, true), // a signature 60 s in the future
      (timestamp + 61, false), // a signature 61 s old
      (timestamp - 61, false), // a signature 61 s in the future
    ];
    for (final (i, (now, fresh)) in cases.indexed) {
      if (fresh) {
        expect(verify(now), payload, reason: '$i');
        expect(open(now), payload, reason: '$i');
      } else {
        expect(() => verify(now), throwsRejection('stale'), reason: '$i');
        expect(() => open(now), throwsRejection('stale'), reason: '$i');
      }
    }
  });

  // Tests that signing and sealing embed exactly the timestamp given, which a
  // check allowing no drift accepts at that second only.
  test('signing at a given time', () {
    final signer = xdsa.SecretKey.generate();
    final recipient = xhpke.SecretKey.generate();
    const timestamp = 1700000000;

    final signed = cose.signAt(
      msgToEmbed: 'payload',
      msgToAuth: 'context',
      signer: signer,
      domain: domain,
      timestamp: timestamp,
    );
    final detached = cose.signDetachedAt(
      msgToAuth: 'payload',
      signer: signer,
      domain: domain,
      timestamp: timestamp,
    );
    final sealed = cose.sealAt(
      msgToSeal: 'payload',
      msgToAuth: 'context',
      signer: signer,
      recipient: recipient.publicKey(),
      domain: domain,
      padding: cose.Padding.buckets(floor: 8192, step: 20),
      timestamp: timestamp,
    );
    final checks = <void Function(int now)>[
      // the embedded signature
      (now) => cose.verifyAt<String>(
        msgToCheck: signed,
        msgToAuth: 'context',
        verifier: signer.publicKey(),
        domain: domain,
        maxDriftSecs: 0,
        now: now,
      ),
      // the detached signature
      (now) => cose.verifyDetachedAt(
        msgToCheck: detached,
        msgToAuth: 'payload',
        verifier: signer.publicKey(),
        domain: domain,
        maxDriftSecs: 0,
        now: now,
      ),
      // the sealed message
      (now) => cose.openAt<String>(
        msgToOpen: sealed,
        msgToAuth: 'context',
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
        maxDriftSecs: 0,
        now: now,
      ),
    ];
    for (final (i, check) in checks.indexed) {
      expect(() => check(timestamp), returnsNormally, reason: '$i');
      expect(
        () => check(timestamp - 1),
        throwsRejection('stale'),
        reason: '$i',
      );
      expect(
        () => check(timestamp + 1),
        throwsRejection('stale'),
        reason: '$i',
      );
    }
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
      padding: const cose.Padding.none(),
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
      () => cose.verifyAt<String>(
        msgToCheck: signed,
        msgToAuth: null,
        verifier: signer.publicKey(),
        domain: domain,
        maxDriftSecs: -1,
        now: 0,
      ),
      () => cose.verifyDetachedAt(
        msgToCheck: detached,
        msgToAuth: 'payload',
        verifier: signer.publicKey(),
        domain: domain,
        maxDriftSecs: -1,
        now: 0,
      ),
      () => cose.openAt<String>(
        msgToOpen: sealed,
        msgToAuth: null,
        recipient: recipient,
        sender: signer.publicKey(),
        domain: domain,
        maxDriftSecs: -1,
        now: 0,
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
