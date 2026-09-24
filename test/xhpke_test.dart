// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:darkbio_crypto/cose.dart' as cose;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:darkbio_crypto/xdsa.dart' as xdsa;
import 'package:darkbio_crypto/xhpke.dart' as xhpke;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  setUpAll(() => RustLib.init());

  // Tests that a sealed message opens only with the same key, authenticated
  // message and domain, and only while intact.
  test('seal and open', () {
    final secret = xhpke.SecretKey.generate();
    final header = utf8.encode('header');
    final domain = utf8.encode('domain');
    final (encapKey, ciphertext) = secret.publicKey().seal(
      msgToSeal: utf8.encode('secret'),
      msgToAuth: header,
      domain: domain,
    );
    final plaintext = secret.open(
      sessionKey: encapKey,
      msgToOpen: ciphertext,
      msgToAuth: header,
      domain: domain,
    );
    expect(utf8.decode(plaintext), 'secret');

    final tampered = Uint8List.fromList(ciphertext)..[0] ^= 1;
    final cases = <void Function()>[
      () => xhpke.SecretKey.generate().open(
        sessionKey: encapKey,
        msgToOpen: ciphertext,
        msgToAuth: header,
        domain: domain,
      ),
      () => secret.open(
        sessionKey: encapKey,
        msgToOpen: ciphertext,
        msgToAuth: utf8.encode('other'),
        domain: domain,
      ),
      () => secret.open(
        sessionKey: encapKey,
        msgToOpen: ciphertext,
        msgToAuth: header,
        domain: utf8.encode('other'),
      ),
      () => secret.open(
        sessionKey: encapKey,
        msgToOpen: tampered,
        msgToAuth: header,
        domain: domain,
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that a receiver opens a sender's messages in order only, and keeps
  // its place after rejecting one out of order, one with the wrong
  // authenticated message and a replay.
  test('sender and receiver', () {
    final secret = xhpke.SecretKey.generate();
    final domain = utf8.encode('domain');
    final (sender, encapKey) = secret.publicKey().newSender(domain: domain);
    final receiver = secret.newReceiver(encapKey: encapKey, domain: domain);

    final header = utf8.encode('header');
    final first = sender.seal(
      msgToSeal: utf8.encode('first'),
      msgToAuth: header,
    );
    final second = sender.seal(
      msgToSeal: utf8.encode('second'),
      msgToAuth: header,
    );
    expect(
      () => receiver.open(msgToOpen: second, msgToAuth: header),
      throwsRejection(),
    );
    expect(
      () => receiver.open(msgToOpen: first, msgToAuth: utf8.encode('other')),
      throwsRejection(),
    );
    expect(
      utf8.decode(receiver.open(msgToOpen: first, msgToAuth: header)),
      'first',
    );
    expect(
      () => receiver.open(msgToOpen: first, msgToAuth: header),
      throwsRejection(),
    );
    expect(
      utf8.decode(receiver.open(msgToOpen: second, msgToAuth: header)),
      'second',
    );
  });

  // Tests against the draft-connolly-cfrg-xwing-kem vectors, copied from
  // crypto-rs. The private key must parse into the published seed, encode
  // back into the published PEM, and expand into the published public key.
  test('IETF vectors', () {
    final fx = fixture('xhpke/ietf');
    final secret = xhpke.SecretKey.fromPem(fx['secret_pem'] as String);
    expect(secret.toBytes(), hex(fx['seed'] as String));
    expect(secret.toPem().trim(), fx['secret_pem']);
    expect(secret.publicKey().toPem().trim(), fx['public_pem']);
  });

  // Tests that keys survive their byte, DER and PEM encodings.
  test('encodings round trip', () {
    final secret = xhpke.SecretKey.generate();
    final public = secret.publicKey();

    final seed = secret.toBytes();
    expect(xhpke.SecretKey.fromBytes(seed).toBytes(), seed);
    expect(xhpke.SecretKey.fromDer(secret.toDer()).toBytes(), seed);
    expect(xhpke.SecretKey.fromPem(secret.toPem()).toBytes(), seed);

    final key = public.toBytes();
    expect(xhpke.PublicKey.fromBytes(key).toBytes(), key);
    expect(xhpke.PublicKey.fromDer(public.toDer()).toBytes(), key);
    expect(xhpke.PublicKey.fromPem(public.toPem()).toBytes(), key);
  });

  // Tests that fingerprints compare and hash by their bytes.
  test('fingerprint equality', () {
    final key = xhpke.SecretKey.generate().publicKey();
    final restored = xhpke.PublicKey.fromPem(key.toPem());

    expect(restored.fingerprint(), key.fingerprint());
    expect(restored.fingerprint().hashCode, key.fingerprint().hashCode);
    expect({restored.fingerprint(), key.fingerprint()}, hasLength(1));
    expect(
      xhpke.Fingerprint.fromBytes(key.fingerprint().toBytes()),
      key.fingerprint(),
    );
    expect(xhpke.SecretKey.generate().fingerprint(), isNot(key.fingerprint()));
  });

  // Tests that wrongly sized or malformed inputs are rejected, including a
  // public key whose ML-KEM coefficients fall outside [0, 3329).
  test('invalid inputs', () {
    final secret = xhpke.SecretKey.generate();
    final domain = utf8.encode('domain');
    final cases = <void Function()>[
      () => xhpke.SecretKey.fromBytes(Uint8List(31)),
      () => xhpke.PublicKey.fromBytes(Uint8List(1215)),
      () => xhpke.PublicKey.fromBytes(
        Uint8List.fromList(List.filled(1216, 0xff)),
      ),
      () => xhpke.Fingerprint.fromBytes(Uint8List(33)),
      () => xhpke.PublicKey.fromDer(Uint8List(16)),
      () => xhpke.SecretKey.fromPem('not a pem'),
      () => secret.newReceiver(encapKey: Uint8List(1119), domain: domain),
      () => secret.open(
        sessionKey: Uint8List(1119),
        msgToOpen: Uint8List(32),
        msgToAuth: Uint8List(0),
        domain: domain,
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that disposed secret keys, senders and receivers refuse every
  // operation, directly and through COSE, that a receiver created from a key
  // before its disposal stays usable, and that disposing again does nothing.
  test('dispose', () {
    final secret = xhpke.SecretKey.generate();
    final signer = xdsa.SecretKey.generate();
    final domain = utf8.encode('dispose');
    final aad = Uint8List(0);
    final (sender, encapKey) = secret.publicKey().newSender(domain: domain);
    final receiver = secret.newReceiver(encapKey: encapKey, domain: domain);
    final (sessionKey, ciphertext) = secret.publicKey().seal(
      msgToSeal: Uint8List(1),
      msgToAuth: aad,
      domain: domain,
    );
    final sealed = cose.seal(
      msgToSeal: 'payload',
      msgToAuth: null,
      signer: signer,
      recipient: secret.publicKey(),
      domain: domain,
    );

    secret.dispose();
    final operations = <String, void Function()>{
      'publicKey': () => secret.publicKey(),
      'fingerprint': () => secret.fingerprint(),
      'newReceiver': () =>
          secret.newReceiver(encapKey: encapKey, domain: domain),
      'open': () => secret.open(
        sessionKey: sessionKey,
        msgToOpen: ciphertext,
        msgToAuth: aad,
        domain: domain,
      ),
      'toBytes': () => secret.toBytes(),
      'toDer': () => secret.toDer(),
      'toPem': () => secret.toPem(),
      'cose.open': () => cose.open<String>(
        msgToOpen: sealed,
        msgToAuth: null,
        recipient: secret,
        sender: signer.publicKey(),
        domain: domain,
      ),
    };
    for (final MapEntry(key: name, value: run) in operations.entries) {
      expect(run, throwsDisposed(), reason: name);
    }

    final message = utf8.encode('message');
    final sealedMessage = sender.seal(msgToSeal: message, msgToAuth: aad);
    expect(receiver.open(msgToOpen: sealedMessage, msgToAuth: aad), message);

    sender.dispose();
    receiver.dispose();
    expect(
      () => sender.seal(msgToSeal: message, msgToAuth: aad),
      throwsDisposed(),
    );
    expect(
      () => receiver.open(msgToOpen: sealedMessage, msgToAuth: aad),
      throwsDisposed(),
    );

    secret.dispose();
    sender.dispose();
    receiver.dispose();
  });
}
