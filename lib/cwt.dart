// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// CBOR Web Tokens (CWT) on top of COSE Sign1.
///
/// <https://datatracker.ietf.org/doc/html/rfc8392>
///
/// Tokens carry a set of [Claims] encoded as a CBOR map. Standard CWT and
/// EAT claims have typed accessors; custom claims use integer keys via
/// `operator[]`.
///
/// ## Example
///
/// ```dart
/// import 'package:darkbio_crypto/cwt.dart' as cwt;
/// import 'package:darkbio_crypto/xdsa.dart' as xdsa;
///
/// final issuerKey = xdsa.SecretKey.generate();
/// final deviceKey = xdsa.SecretKey.generate();
///
/// // Issue a token
/// final claims = cwt.Claims()
///   ..subject = 'device-abc'
///   ..notBefore = 1000000
///   ..expiration = 2000000
///   ..setConfirmXdsa(deviceKey.publicKey());
///
/// final token = cwt.issue(
///   claims: claims,
///   signer: issuerKey,
///   domain: 'device-cert',
/// );
///
/// // Verify a token
/// final verified = cwt.verify(
///   token: token,
///   verifier: issuerKey.publicKey(),
///   domain: 'device-cert',
///   now: 1500000,
/// );
/// print(verified.subject); // 'device-abc'
/// ```
library;

import 'dart:typed_data';

import 'package:cbor/simple.dart' as cbor;

import 'src/generated/api/cwt.dart' as ffi;
import 'xdsa.dart'
    as xdsa
    show
        SecretKey,
        PublicKey,
        Fingerprint,
        SecretKeyInternal,
        PublicKeyInternal,
        FingerprintInternal;
import 'xhpke.dart' as xhpke show PublicKey;

// COSE algorithm identifiers used in Confirm claim encoding.
const int _algorithmIdXdsa = -70000;
const int _algorithmIdXhpke = -70001;

/// A CWT claims set with typed accessors for standard CWT (RFC 8392) and
/// EAT (RFC 9711) claims.
///
/// Standard claims are exposed as typed properties. Custom or application-
/// specific claims can be accessed via `operator[]` using their integer key.
class Claims {
  final Map<int, Object?> _map;

  /// Creates an empty claims set.
  Claims() : _map = {};

  Claims._(this._map);

  /// Issuer: identifies the principal that issued the token (key 1).
  String? get issuer => _map[1] as String?;
  set issuer(String? value) => _set(1, value);

  /// Subject: identifies the principal that is the subject of the token (key 2).
  String? get subject => _map[2] as String?;
  set subject(String? value) => _set(2, value);

  /// Audience: identifies the recipients the token is intended for (key 3).
  String? get audience => _map[3] as String?;
  set audience(String? value) => _set(3, value);

  /// Expiration: the time on or after which the token must not be accepted
  /// (key 4, Unix timestamp in seconds).
  int? get expiration => _map[4] as int?;
  set expiration(int? value) => _set(4, value);

  /// NotBefore: the time before which the token must not be accepted
  /// (key 5, Unix timestamp in seconds).
  int? get notBefore => _map[5] as int?;
  set notBefore(int? value) => _set(5, value);

  /// IssuedAt: the time at which the token was issued
  /// (key 6, Unix timestamp in seconds).
  int? get issuedAt => _map[6] as int?;
  set issuedAt(int? value) => _set(6, value);

  /// TokenID: a unique identifier for the token (key 7).
  Uint8List? get tokenId => _map[7] as Uint8List?;
  set tokenId(Uint8List? value) => _set(7, value);

  /// Sets the Confirm claim to bind an xDSA public key to this token.
  void setConfirmXdsa(xdsa.PublicKey key) {
    _map[8] = {
      1: {1: _algorithmIdXdsa, -2: key.toBytes()},
    };
  }

  /// Sets the Confirm claim to bind an xHPKE public key to this token.
  void setConfirmXhpke(xhpke.PublicKey key) {
    _map[8] = {
      1: {1: _algorithmIdXhpke, -2: key.toBytes()},
    };
  }

  /// Extracts the bound xDSA public key from the Confirm claim, or null if
  /// absent or a different key type.
  xdsa.PublicKey? getConfirmXdsa() {
    final (kty, bytes) = _readConfirm();
    if (kty != _algorithmIdXdsa || bytes == null) return null;
    return xdsa.PublicKey.fromBytes(bytes);
  }

  /// Extracts the bound xHPKE public key from the Confirm claim, or null if
  /// absent or a different key type.
  xhpke.PublicKey? getConfirmXhpke() {
    final (kty, bytes) = _readConfirm();
    if (kty != _algorithmIdXhpke || bytes == null) return null;
    return xhpke.PublicKey.fromBytes(bytes);
  }

  /// Reads the Confirm claim's key type and raw key bytes.
  /// Returns (null, null) if the claim is absent or malformed.
  (int?, Uint8List?) _readConfirm() {
    final cnf = _map[8];
    if (cnf is! Map) return (null, null);
    final coseKey = cnf[1];
    if (coseKey is! Map) return (null, null);
    final kty = coseKey[1];
    final x = coseKey[-2];
    if (kty is! int || x is! Uint8List) return (null, null);
    return (kty, x);
  }

  /// UEID: a globally unique device identifier (key 256).
  Uint8List? get ueid => _map[256] as Uint8List?;
  set ueid(Uint8List? value) => _set(256, value);

  /// OEMID: hardware manufacturer identifier (key 258).
  ///
  /// Use [setOemidRandom], [setOemidIeee], or [setOemidPen] to set.
  /// The getter returns the raw CBOR value (Uint8List or int).
  Object? get oemid => _map[258];

  /// Sets OEMID to a 16-byte random manufacturer identifier.
  void setOemidRandom(Uint8List id) {
    assert(id.length == 16);
    _map[258] = id;
  }

  /// Sets OEMID to a 3-byte IEEE OUI/MA-L.
  void setOemidIeee(Uint8List id) {
    assert(id.length == 3);
    _map[258] = id;
  }

  /// Sets OEMID to an IANA Private Enterprise Number.
  void setOemidPen(int pen) => _map[258] = pen;

  /// HwModel: product or board model identifier (key 259).
  Uint8List? get hwModel => _map[259] as Uint8List?;
  set hwModel(Uint8List? value) => _set(259, value);

  /// HwVersion: hardware revision identifier (key 260).
  /// Stored as a 1-element CBOR array per RFC 9711 Section 4.2.5.
  String? get hwVersion {
    final v = _map[260];
    if (v is List && v.isNotEmpty) return v[0] as String?;
    return null;
  }

  set hwVersion(String? value) => _set(260, value != null ? [value] : null);

  /// Uptime: seconds since last boot (key 261).
  int? get uptime => _map[261] as int?;
  set uptime(int? value) => _set(261, value);

  /// OemBoot: whether the boot chain is OEM-authorized (key 262).
  bool? get oemBoot => _map[262] as bool?;
  set oemBoot(bool? value) => _set(262, value);

  /// DebugStatus: debug port state (key 263).
  DebugState? get debugStatus {
    final v = _map[263];
    if (v is! int || v < 0 || v > 4) return null;
    return DebugState.values[v];
  }

  set debugStatus(DebugState? value) => _set(263, value?.index);

  /// BootCount: number of times the device has booted (key 267).
  int? get bootCount => _map[267] as int?;
  set bootCount(int? value) => _set(267, value);

  /// BootSeed: random value unique to the current boot cycle (key 268).
  Uint8List? get bootSeed => _map[268] as Uint8List?;
  set bootSeed(Uint8List? value) => _set(268, value);

  /// SwName: name of the firmware or software (key 270).
  String? get swName => _map[270] as String?;
  set swName(String? value) => _set(270, value);

  /// SwVersion: software version identifier (key 271).
  /// Stored as a 1-element CBOR array per RFC 9711 Section 4.2.7.
  String? get swVersion {
    final v = _map[271];
    if (v is List && v.isNotEmpty) return v[0] as String?;
    return null;
  }

  set swVersion(String? value) => _set(271, value != null ? [value] : null);

  /// IntendedUse: the token's purpose (key 275).
  IntendedUse? get intendedUse {
    final v = _map[275];
    if (v is! int || v < 1 || v > 5) return null;
    return IntendedUse.values[v - 1];
  }

  set intendedUse(IntendedUse? value) =>
      _set(275, value != null ? value.index + 1 : null);

  /// Gets a custom claim by its integer key.
  Object? operator [](int key) => _map[key];

  /// Sets a custom claim by its integer key.
  void operator []=(int key, Object? value) => _set(key, value);

  void _set(int key, Object? value) {
    if (value != null) {
      _map[key] = value;
    } else {
      _map.remove(key);
    }
  }

  /// Encodes the claims to CBOR bytes.
  Uint8List _encode() => Uint8List.fromList(cbor.cbor.encode(_map));

  /// Decodes claims from CBOR bytes.
  static Claims _decode(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes);
    if (decoded is! Map) {
      throw FormatException('CWT claims must be a CBOR map');
    }
    final map = <int, Object?>{};
    for (final entry in decoded.entries) {
      if (entry.key is int) {
        map[entry.key as int] = entry.value;
      }
    }
    return Claims._(map);
  }
}

/// Debug port state per RFC 9711 Section 4.2.9.
enum DebugState {
  /// Debug is currently enabled.
  enabled,

  /// Debug is currently disabled.
  disabled,

  /// Debug was disabled at boot and has not been enabled since.
  disabledSinceBoot,

  /// Debug is disabled and cannot be re-enabled.
  disabledPermanently,

  /// All debug, including DMA-based, is permanently disabled.
  disabledFullyPermanently,
}

/// Token intended purpose per RFC 9711 Section 4.3.3.
enum IntendedUse {
  /// General-purpose attestation.
  generic,

  /// Attestation for service registration.
  registration,

  /// Attestation prior to key/config provisioning.
  provisioning,

  /// Attestation for certificate signing requests.
  certIssuance,

  /// Attestation accompanying a proof-of-possession.
  proofOfPossession,
}

/// Issues a CWT by signing the [claims] with COSE Sign1.
///
/// Uses the current system time as the COSE signature timestamp.
///
/// - [claims]: The claims to include in the token
/// - [signer]: The xDSA secret key to sign with
/// - [domain]: Application-specific domain separator
Uint8List issue({
  required Claims claims,
  required xdsa.SecretKey signer,
  required String domain,
}) => ffi.cwtIssue(
  claimsCbor: claims._encode(),
  signer: signer.inner,
  domain: domain,
);

/// Verifies a CWT's COSE signature and temporal validity, then returns the
/// decoded claims.
///
/// When [now] is provided (Unix timestamp in seconds), temporal claims are
/// validated: nbf must be present and `nbf <= now`, and if exp is present
/// then `now < exp`. When [now] is null, temporal validation is skipped.
///
/// - [token]: The serialized CWT
/// - [verifier]: The xDSA public key to verify against
/// - [domain]: Application-specific domain separator
/// - [now]: Current Unix timestamp for temporal validation (null to skip)
Claims verify({
  required Uint8List token,
  required xdsa.PublicKey verifier,
  required String domain,
  int? now,
}) => Claims._decode(
  ffi.cwtVerify(
    token: token,
    verifier: verifier.inner,
    domain: domain,
    now: now != null ? BigInt.from(now) : null,
  ),
);

/// Extracts the signer's fingerprint from a CWT without verifying.
///
/// The returned data is unauthenticated. Use this to look up the appropriate
/// verification key before calling [verify].
xdsa.Fingerprint signer({required Uint8List token}) =>
    xdsa.FingerprintInternal.wrap(ffi.cwtSigner(token: token));

/// Extracts claims from a CWT without verifying the signature.
///
/// **Warning**: The returned payload is unauthenticated and should not be
/// trusted until verified with [verify]. Use [signer] to extract the signer's
/// fingerprint for key lookup.
Claims peek({required Uint8List token}) =>
    Claims._decode(ffi.cwtPeek(token: token));
