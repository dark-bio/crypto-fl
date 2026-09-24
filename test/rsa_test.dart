// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:darkbio_crypto/rsa.dart' as rsa;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  late rsa.SecretKey secret;

  setUpAll(() async {
    await RustLib.init();
    secret = rsa.SecretKey.generate();
  });

  // Tests that a signature verifies for the signed message and key only.
  test('sign and verify', () {
    final message = utf8.encode('message');
    final signature = secret.sign(message);

    secret.publicKey().verify(message, signature);
    expect(
      () => secret.publicKey().verify(utf8.encode('other'), signature),
      throwsRejection(),
    );
    expect(
      () => rsa.SecretKey.generate().publicKey().verify(message, signature),
      throwsRejection(),
    );
  });

  // Tests that keys and signatures survive their byte, DER and PEM encodings.
  test('encodings round trip', () {
    final public = secret.publicKey();
    final signature = secret.sign(utf8.encode('message'));

    final bytes = secret.toBytes();
    expect(rsa.SecretKey.fromBytes(bytes).toBytes(), bytes);
    expect(rsa.SecretKey.fromDer(secret.toDer()).toBytes(), bytes);
    expect(rsa.SecretKey.fromPem(secret.toPem()).toBytes(), bytes);

    final key = public.toBytes();
    expect(rsa.PublicKey.fromBytes(key).toBytes(), key);
    expect(rsa.PublicKey.fromDer(public.toDer()).toBytes(), key);
    expect(rsa.PublicKey.fromPem(public.toPem()).toBytes(), key);

    final sig = signature.toBytes();
    expect(rsa.Signature.fromBytes(sig).toBytes(), sig);
  });

  // Tests that fingerprints compare and hash by their bytes.
  test('fingerprint equality', () {
    final key = secret.publicKey();
    final restored = rsa.PublicKey.fromPem(key.toPem());

    expect(restored.fingerprint(), key.fingerprint());
    expect(restored.fingerprint().hashCode, key.fingerprint().hashCode);
    expect({restored.fingerprint(), key.fingerprint()}, hasLength(1));
    expect(secret.fingerprint(), key.fingerprint());
    expect(
      rsa.Fingerprint.fromBytes(key.fingerprint().toBytes()),
      key.fingerprint(),
    );
    expect(rsa.SecretKey.generate().fingerprint(), isNot(key.fingerprint()));
  });

  // Tests the fingerprint against one computed with PyCryptodome, the SHA-256
  // of the little-endian modulus and exponent, copied from crypto-rs.
  test('fingerprint vector', () {
    final key = rsa.PublicKey.fromPem('''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCy10x2mE+e8jR2U+gU5
ySA2ifBk57tOT58EEHFe14KJteuE+dqmjJr7CvzxpczM0HaPWI2CrBMWRBJZSXuD
tZlQNU/y8ii5D2YCqnKddf/VAJJN6R7D5G9GDm94Ne9tSurUO/Ln43iDreVifp/h
yRzr4b8o5jtGkOdXodI0slLulPXwPqq7TzuA/5lFUQyZgi0shsyDHeF2p800lmfC
Vi42oSHTDzmWFKxqSAjscLfSWqMN+6IAGpUVR502/D5JJTqPaa9Gt2XUED98lfwO
YJoF1y4tgZENG9svBTrg/yYwVy+CrPZ1FZ/5zDGhYQ8Zi92WfQLrwfeAEQdDL7mY
fQIDAQAB
-----END PUBLIC KEY-----''');
    expect(
      key.fingerprint().toBytes(),
      hex('1e2eaa59f13165ce5c3b4e028fd259767c2ee8d43d5d5ba7debf9d31834b46db'),
    );
  });

  // Tests that wrongly sized or malformed inputs are rejected, including a
  // public key with an exponent other than 65537.
  test('invalid inputs', () {
    final exponent = Uint8List.fromList(secret.publicKey().toBytes())
      ..[263] = 3;
    final cases = <void Function()>[
      () => rsa.SecretKey.fromBytes(Uint8List(519)),
      () => rsa.SecretKey.fromBytes(Uint8List(520)),
      () => rsa.PublicKey.fromBytes(Uint8List(263)),
      () => rsa.PublicKey.fromBytes(Uint8List(264)),
      () => rsa.PublicKey.fromBytes(exponent),
      () => rsa.Signature.fromBytes(Uint8List(255)),
      () => rsa.Fingerprint.fromBytes(Uint8List(31)),
      () => rsa.PublicKey.fromDer(Uint8List(16)),
      () => rsa.SecretKey.fromPem('not a pem'),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });
}
