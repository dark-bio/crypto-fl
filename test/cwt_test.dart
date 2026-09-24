// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:darkbio_crypto/cwt.dart' as cwt;
import 'package:darkbio_crypto/src/generated/frb_generated.dart';
import 'package:darkbio_crypto/xdsa.dart' as xdsa;
import 'package:darkbio_crypto/xhpke.dart' as xhpke;
import 'package:flutter_test/flutter_test.dart';

import 'helpers.dart';

void main() {
  setUpAll(() => RustLib.init());

  final domain = utf8.encode('domain');

  // Tests that claims set in any key order issue and verify, and that every
  // standard claim survives the round trip.
  test('claims round trip', () {
    final issuer = xdsa.SecretKey.generate();
    final device = xdsa.SecretKey.generate();
    final ueid = Uint8List.fromList([1, ...List.filled(16, 7)]);
    final oemid = Uint8List.fromList(List.filled(16, 9));

    final claims = cwt.Claims()
      ..intendedUse = cwt.IntendedUse.registration
      ..swVersion = '1.2.3'
      ..swName = 'firmware'
      ..bootSeed = Uint8List.fromList([1, 2, 3])
      ..bootCount = 42
      ..debugStatus = cwt.DebugState.disabledPermanently
      ..oemBoot = true
      ..uptime = 3600
      ..hwVersion = 'rev1'
      ..hwModel = Uint8List.fromList([4, 5, 6])
      ..setOemidRandom(oemid)
      ..ueid = ueid
      ..setConfirmXdsa(device.publicKey())
      ..tokenId = Uint8List.fromList([7, 8])
      ..issuedAt = 1000
      ..notBefore = 1000
      ..expiration = 2000
      ..audience = 'audience'
      ..subject = 'subject'
      ..issuer = 'issuer'
      ..[-2] = 'minus two'
      ..[-1] = 'minus one';

    final token = cwt.issue(claims: claims, signer: issuer, domain: domain);
    final got = cwt.verify(
      token: token,
      verifier: issuer.publicKey(),
      domain: domain,
      now: 1500,
    );
    expect(got.issuer, 'issuer');
    expect(got.subject, 'subject');
    expect(got.audience, 'audience');
    expect(got.expiration, 2000);
    expect(got.notBefore, 1000);
    expect(got.issuedAt, 1000);
    expect(got.tokenId, [7, 8]);
    expect(got.getConfirmXdsa()!.toBytes(), device.publicKey().toBytes());
    expect(got.getConfirmXhpke(), isNull);
    expect(got.ueid, ueid);
    expect(got.oemid, oemid);
    expect(got.hwModel, [4, 5, 6]);
    expect(got.hwVersion, 'rev1');
    expect(got.uptime, 3600);
    expect(got.oemBoot, isTrue);
    expect(got.debugStatus, cwt.DebugState.disabledPermanently);
    expect(got.bootCount, 42);
    expect(got.bootSeed, [1, 2, 3]);
    expect(got.swName, 'firmware');
    expect(got.swVersion, '1.2.3');
    expect(got.intendedUse, cwt.IntendedUse.registration);
    expect(got[-1], 'minus one');
    expect(got[-2], 'minus two');
  });

  // Tests that an xHPKE confirmation key round trips and is not mistaken for
  // an xDSA one.
  test('xhpke confirmation', () {
    final issuer = xdsa.SecretKey.generate();
    final device = xhpke.SecretKey.generate();
    final claims = cwt.Claims()..setConfirmXhpke(device.publicKey());

    final token = cwt.issue(claims: claims, signer: issuer, domain: domain);
    final got = cwt.verify(
      token: token,
      verifier: issuer.publicKey(),
      domain: domain,
    );
    expect(got.getConfirmXhpke()!.toBytes(), device.publicKey().toBytes());
    expect(got.getConfirmXdsa(), isNull);
  });

  // Tests the time checks against the nbf and exp claims, with nbf inclusive
  // and exp exclusive, skipped entirely without a current time and refused
  // with a negative one.
  test('temporal validity', () {
    final issuer = xdsa.SecretKey.generate();
    Uint8List issue(int? nbf, int? exp) => cwt.issue(
      claims: cwt.Claims()
        ..notBefore = nbf
        ..expiration = exp,
      signer: issuer,
      domain: domain,
    );
    final cases = <(Uint8List, int?, Matcher)>[
      (issue(100, 200), 150, returnsNormally),
      (issue(100, 200), 100, returnsNormally),
      (issue(100, null), 1 << 40, returnsNormally),
      (issue(null, 200), null, returnsNormally),
      (issue(100, 200), 99, throwsRejection('not yet valid')),
      (issue(100, 200), 200, throwsRejection('already expired')),
      (issue(null, 200), 150, throwsRejection('missing nbf')),
      (issue(100, 200), -1, throwsArgumentError),
    ];
    for (final (i, (token, now, matcher)) in cases.indexed) {
      expect(
        () => cwt.verify(
          token: token,
          verifier: issuer.publicKey(),
          domain: domain,
          now: now,
        ),
        matcher,
        reason: '$i',
      );
    }
  });

  // Tests that a token verifies only under its issuer's key and domain.
  test('wrong key and domain', () {
    final issuer = xdsa.SecretKey.generate();
    final token = cwt.issue(
      claims: cwt.Claims()..subject = 'subject',
      signer: issuer,
      domain: domain,
    );
    final cases = <void Function()>[
      () => cwt.verify(
        token: token,
        verifier: xdsa.SecretKey.generate().publicKey(),
        domain: domain,
      ),
      () => cwt.verify(
        token: token,
        verifier: issuer.publicKey(),
        domain: utf8.encode('other'),
      ),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that decoded claims issue again unchanged, with byte strings staying
  // byte strings and arrays staying arrays, nested ones and the confirmation
  // key included.
  test('reissue decoded claims', () {
    final issuer = xdsa.SecretKey.generate();
    final device = xdsa.SecretKey.generate();
    final claims = cwt.Claims()
      ..tokenId = Uint8List.fromList([1, 2])
      ..[-1] = {
        1: Uint8List.fromList([3, 4]),
        2: [5, 6],
        3: [],
      }
      ..setConfirmXdsa(device.publicKey());

    final token = cwt.issue(claims: claims, signer: issuer, domain: domain);
    final reissued = cwt.issue(
      claims: cwt.peek(token: token),
      signer: issuer,
      domain: domain,
    );
    final got = cwt.peek(token: reissued);
    final custom = got[-1] as Map;
    expect(got.tokenId, [1, 2]);
    expect(custom[1], allOf(isA<Uint8List>(), [3, 4]));
    expect(custom[2], allOf(isNot(isA<Uint8List>()), [5, 6]));
    expect(custom[3], allOf(isNot(isA<Uint8List>()), isEmpty));
    expect(got.getConfirmXdsa()!.toBytes(), device.publicKey().toBytes());
  });

  // Tests that integers wider than 53 bits read back as int, in standard
  // claims, custom claims and claim keys alike.
  test('wide integers', () {
    final issuer = xdsa.SecretKey.generate();
    final claims = cwt.Claims()
      ..bootCount = 1 << 53
      ..expiration = 0x7fffffffffffffff
      ..[1 << 53] = -(1 << 60);

    final token = cwt.issue(claims: claims, signer: issuer, domain: domain);
    final got = cwt.peek(token: token);
    expect(got.bootCount, 1 << 53);
    expect(got.expiration, 0x7fffffffffffffff);
    expect(got[1 << 53], -(1 << 60));
  });

  // Tests that claim sets of 256 entries and more issue and read back.
  test('large claim sets', () {
    final issuer = xdsa.SecretKey.generate();
    final claims = cwt.Claims();
    for (var i = 0; i < 300; i++) {
      claims[1000 + i] = i;
    }
    final token = cwt.issue(claims: claims, signer: issuer, domain: domain);
    final got = cwt.peek(token: token);
    for (var i = 0; i < 300; i++) {
      expect(got[1000 + i], i, reason: '$i');
    }
  });

  // Tests that a validly signed claims set outside the supported CBOR subset,
  // one carrying its subject twice, is refused when verified or peeked.
  test('noncanonical claims', () {
    final fx = fixture('cwt/noncanonical');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final token = hex(fx['token'] as String);

    final cases = <void Function()>[
      () => cwt.verify(
        token: token,
        verifier: signer.publicKey(),
        domain: hex(fx['domain'] as String),
        now: 0,
      ),
      () => cwt.peek(token: token),
    ];
    for (final (i, run) in cases.indexed) {
      expect(run, throwsRejection(), reason: '$i');
    }
  });

  // Tests that the signer and the claims can be read without verifying.
  test('signer and peek', () {
    final issuer = xdsa.SecretKey.generate();
    final token = cwt.issue(
      claims: cwt.Claims()..subject = 'subject',
      signer: issuer,
      domain: domain,
    );
    expect(cwt.signer(token: token), issuer.fingerprint());
    expect(cwt.peek(token: token).subject, 'subject');
  });

  // Tests that the v0.16 fixture corpus still validates, since that was in the
  // first public release of the Ark, so the format cannot change anymore.
  test('v0.16 fixtures', () {
    final fx = fixture('cwt/v0.16');
    final signer = xdsa.SecretKey.fromBytes(hex(fx['xdsa_seed'] as String));
    final domain = hex(fx['domain'] as String);
    final now = fx['now'] as int;

    final valid = hex(fx['valid'] as String);
    final claims = cwt.verify(
      token: valid,
      verifier: signer.publicKey(),
      domain: domain,
      now: now,
    );
    expect(claims.subject, 'fixture');
    expect(claims.expiration, 4102444800);
    expect(claims.notBefore, 1500000000);
    expect(claims.getConfirmXdsa()!.toBytes(), signer.publicKey().toBytes());

    expect(
      () => cwt.verify(
        token: hex(fx['expired'] as String),
        verifier: signer.publicKey(),
        domain: domain,
        now: now,
      ),
      throwsRejection('already expired'),
    );
    expect(
      () => cwt.verify(
        token: hex(fx['premature'] as String),
        verifier: signer.publicKey(),
        domain: domain,
        now: now,
      ),
      throwsRejection('not yet valid'),
    );
    final tampered = Uint8List.fromList(valid)..[valid.length - 1] ^= 1;
    expect(
      () => cwt.verify(
        token: tampered,
        verifier: signer.publicKey(),
        domain: domain,
        now: now,
      ),
      throwsRejection(),
    );
  });
}
