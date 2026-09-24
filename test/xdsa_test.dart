// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:darkbio_crypto/xdsa.dart' as xdsa;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  setUpAll(() => RustLib.init());

  // Tests that a signature verifies for the signed message and key only.
  test('sign and verify', () {
    final secret = xdsa.SecretKey.generate();
    final message = utf8.encode('message');
    final signature = secret.sign(message);

    secret.publicKey().verify(message, signature);
    expect(
      () => secret.publicKey().verify(utf8.encode('other'), signature),
      throwsRejection(),
    );
    expect(
      () => xdsa.SecretKey.generate().publicKey().verify(message, signature),
      throwsRejection(),
    );
  });

  // Tests that tampering with either half of the composite signature, the
  // ML-DSA one in front or the Ed25519 one at the end, is rejected.
  test('composite halves', () {
    final secret = xdsa.SecretKey.generate();
    final message = utf8.encode('message');
    final signature = secret.sign(message).toBytes();

    for (final index in [0, signature.length - 1]) {
      final tampered = Uint8List.fromList(signature)..[index] ^= 1;
      expect(
        () => secret.publicKey().verify(
          message,
          xdsa.Signature.fromBytes(tampered),
        ),
        throwsRejection(),
        reason: '$index',
      );
    }
  });

  // Tests against the draft-ietf-lamps-pq-composite-sigs vectors, copied from
  // crypto-rs. The seed must expand into the published public key and PKCS #8
  // encoding, and the published signature must verify.
  test('IETF vectors', () {
    final fx = fixture('xdsa/ietf');
    final secret = xdsa.SecretKey.fromBytes(hex(fx['seed'] as String));
    expect(secret.publicKey().toBytes(), hex(fx['public_key'] as String));
    expect(secret.toDer(), hex(fx['pkcs8'] as String));

    final signature = xdsa.Signature.fromBytes(hex(fx['signature'] as String));
    secret.publicKey().verify(utf8.encode(fx['message'] as String), signature);
  });

  // Tests that keys and signatures survive their byte, DER and PEM encodings.
  test('encodings round trip', () {
    final secret = xdsa.SecretKey.generate();
    final public = secret.publicKey();
    final signature = secret.sign(utf8.encode('message'));

    final seed = secret.toBytes();
    expect(xdsa.SecretKey.fromBytes(seed).toBytes(), seed);
    expect(xdsa.SecretKey.fromDer(secret.toDer()).toBytes(), seed);
    expect(xdsa.SecretKey.fromPem(secret.toPem()).toBytes(), seed);

    final key = public.toBytes();
    expect(xdsa.PublicKey.fromBytes(key).toBytes(), key);
    expect(xdsa.PublicKey.fromDer(public.toDer()).toBytes(), key);
    expect(xdsa.PublicKey.fromPem(public.toPem()).toBytes(), key);

    final sig = signature.toBytes();
    expect(xdsa.Signature.fromBytes(sig).toBytes(), sig);
  });

  // Tests that PEM input may use LF or CRLF line endings, but not a mix.
  test('PEM line endings', () {
    final pem = xdsa.SecretKey.generate().publicKey().toPem();

    xdsa.PublicKey.fromPem(pem.replaceAll('\n', '\r\n'));
    expect(
      () => xdsa.PublicKey.fromPem(pem.replaceFirst('\n', '\r\n')),
      throwsRejection(),
    );
  });

  // Tests that fingerprints compare and hash by their bytes.
  test('fingerprint equality', () {
    final key = xdsa.SecretKey.generate().publicKey();
    final restored = xdsa.PublicKey.fromPem(key.toPem());

    expect(restored.fingerprint(), key.fingerprint());
    expect(restored.fingerprint().hashCode, key.fingerprint().hashCode);
    expect({restored.fingerprint(), key.fingerprint()}, hasLength(1));
    expect(
      xdsa.Fingerprint.fromBytes(key.fingerprint().toBytes()),
      key.fingerprint(),
    );
    expect(xdsa.SecretKey.generate().fingerprint(), isNot(key.fingerprint()));
  });

  // Tests that wrongly sized or malformed inputs are rejected.
  test('invalid inputs', () {
    final cases = <void Function()>[
      () => xdsa.SecretKey.fromBytes(Uint8List(63)),
      () => xdsa.PublicKey.fromBytes(Uint8List(1983)),
      () => xdsa.Signature.fromBytes(Uint8List(3372)),
      () => xdsa.Fingerprint.fromBytes(Uint8List(31)),
      () => xdsa.PublicKey.fromDer(Uint8List(16)),
      () => xdsa.SecretKey.fromPem('not a pem'),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });
}
