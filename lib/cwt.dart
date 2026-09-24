// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/// CBOR Web Tokens on top of COSE Sign1.
///
/// https://datatracker.ietf.org/doc/html/rfc8392
///
/// Tokens carry a set of [Claims] encoded as a CBOR map. Standard CWT and EAT
/// claims have typed accessors; custom claims use integer keys via
/// `operator[]`.
///
/// [verify] checks the signature against the supplied key and, when requested,
/// the `nbf` and `exp` time bounds. Applications must establish trust in that
/// key, check issuer and audience claims, and apply their own attestation
/// policy. EAT claim relationships and proof of possession of a `cnf` key are
/// not automatically checked.
///
/// ## Example
///
/// ```dart
/// import 'dart:convert';
///
/// import 'package:darkbio_crypto/cwt.dart' as cwt;
/// import 'package:darkbio_crypto/xdsa.dart' as xdsa;
///
/// void example() {
///   final issuer = xdsa.SecretKey.generate();
///   final device = xdsa.SecretKey.generate();
///   final domain = utf8.encode('device-cert');
///   const now = 1700000000;
///
///   final claims = cwt.Claims()
///     ..subject = 'ark-0001'
///     ..expiration = now + 3600
///     ..notBefore = now
///     ..setConfirmXdsa(device.publicKey());
///   final token = cwt.issue(claims: claims, signer: issuer, domain: domain);
///
///   final verified = cwt.verify(token: token, verifier: issuer.publicKey(), domain: domain, now: now + 60);
///   assert(verified.subject == 'ark-0001');
/// }
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
/// Standard claims are exposed as typed properties, and setting one to null
/// removes it. Claims may be set in any order. Custom or application-specific
/// claims can be accessed via `operator[]` using their integer key. Claim
/// values must encode into the CBOR subset that the `cbor` library lists.
/// Custom claims read back from a token hold the values the `cbor` package
/// decodes, byte strings as `List<int>`.
///
/// Applications must evaluate the EAT claims against their attestation policy
/// and enforce RFC 9711's relationships between claims. For example, `hwmodel`
/// and `oemboot` require `oemid`, `hwversion` requires `hwmodel`, and
/// `swversion` requires `swname`. [DebugState.disabledPermanently] also
/// requires `oemid`. These relationships are not checked by [verify].
class Claims {
  final Map<int, Object?> _map;

  /// Creates an empty claims set.
  Claims() : _map = {};

  Claims._(this._map);

  /// Identifies the principal that issued the token (key 1), a URI or any
  /// string the ecosystem agrees on.
  String? get issuer => _map[1] as String?;
  set issuer(String? value) => _set(1, value);

  /// Identifies the principal that is the subject of the token (key 2), for a
  /// device its serial or attestation subject.
  String? get subject => _map[2] as String?;
  set subject(String? value) => _set(2, value);

  /// Identifies the recipients the token is intended for (key 3), a URI or
  /// any string the ecosystem agrees on.
  String? get audience => _map[3] as String?;
  set audience(String? value) => _set(3, value);

  /// The time on or after which the token must not be accepted (key 4), in
  /// seconds since the Unix epoch.
  int? get expiration => _map[4] as int?;
  set expiration(int? value) => _set(4, value);

  /// The time before which the token must not be accepted (key 5), in seconds
  /// since the Unix epoch.
  int? get notBefore => _map[5] as int?;
  set notBefore(int? value) => _set(5, value);

  /// The time at which the token was issued (key 6), in seconds since the Unix
  /// epoch.
  int? get issuedAt => _map[6] as int?;
  set issuedAt(int? value) => _set(6, value);

  /// A unique identifier for the token (key 7), opaque bytes unique per token.
  Uint8List? get tokenId => _asBytes(_map[7]);
  set tokenId(Uint8List? value) => _set(7, value);

  /// Binds an xDSA public key to the token via the Confirm claim (key 8,
  /// RFC 8747), replacing any key bound before.
  void setConfirmXdsa(xdsa.PublicKey key) {
    _map[8] = {
      1: {1: _algorithmIdXdsa, -2: key.toBytes()},
    };
  }

  /// Binds an xHPKE public key to the token via the Confirm claim (key 8,
  /// RFC 8747), replacing any key bound before.
  void setConfirmXhpke(xhpke.PublicKey key) {
    _map[8] = {
      1: {1: _algorithmIdXhpke, -2: key.toBytes()},
    };
  }

  /// Extracts the bound xDSA public key from the Confirm claim, or null if
  /// absent or a different key type.
  ///
  /// A verified token authenticates this key binding, but does not prove that
  /// the presenter possesses the corresponding private key. Applications must
  /// check that separately using their protocol's proof-of-possession
  /// mechanism. Throws if the bound key is not a valid xDSA public key.
  xdsa.PublicKey? getConfirmXdsa() {
    final (kty, bytes) = _readConfirm();
    if (kty != _algorithmIdXdsa || bytes == null) return null;
    return xdsa.PublicKey.fromBytes(bytes);
  }

  /// Extracts the bound xHPKE public key from the Confirm claim, or null if
  /// absent or a different key type.
  ///
  /// A verified token authenticates this key binding, but does not prove that
  /// the presenter possesses the corresponding private key. Applications must
  /// check that separately using their protocol's proof-of-possession
  /// mechanism. Throws if the bound key is not a valid xHPKE public key.
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
    if (kty is! int) return (null, null);
    final x = _asBytes(coseKey[-2]);
    if (x == null) return (null, null);
    return (kty, x);
  }

  /// Reads a byte-string claim, normalizing to [Uint8List].
  ///
  /// Workaround for https://github.com/shamblett/cbor/issues/88:
  /// package:cbor decodes CBOR byte strings (major type 2) as `Uint8Buffer`
  /// (a `List<int>`) instead of [Uint8List].
  static Uint8List? _asBytes(Object? v) {
    if (v is Uint8List) return v;
    if (v is List<int>) return Uint8List.fromList(v);
    return null;
  }

  /// A globally unique device identifier such as a serial number or IMEI
  /// (key 256).
  ///
  /// The value is opaque bytes whose first byte is a type prefix per RFC 9711
  /// Section 4.2.1. A RAND UEID is the prefix `0x01` followed by 16, 24, or 32
  /// bytes of random identifier data provisioned once for the device. The
  /// bytes are stored as supplied, so callers must validate the prefix, length
  /// and identifier policy.
  Uint8List? get ueid => _asBytes(_map[256]);
  set ueid(Uint8List? value) => _set(256, value);

  /// Identifies the hardware manufacturer (key 258, RFC 9711 Section 4.2.3),
  /// by a random ID, an IEEE OUI or an IANA PEN.
  ///
  /// Use [setOemidRandom], [setOemidIeee], or [setOemidPen] to set it. The
  /// getter returns the raw CBOR value, the ID bytes as a `List<int>` or the
  /// PEN as an `int`.
  Object? get oemid => _map[258];

  /// Sets OEMID to a 16-byte random manufacturer identifier.
  ///
  /// Throws if [id] is not 16 bytes long.
  void setOemidRandom(Uint8List id) {
    if (id.length != 16) {
      throw ArgumentError.value(id.length, 'id.length', 'must be 16 bytes');
    }
    _map[258] = id;
  }

  /// Sets OEMID to a 3-byte IEEE OUI/MA-L.
  ///
  /// Throws if [id] is not 3 bytes long.
  void setOemidIeee(Uint8List id) {
    if (id.length != 3) {
      throw ArgumentError.value(id.length, 'id.length', 'must be 3 bytes');
    }
    _map[258] = id;
  }

  /// Sets OEMID to an IANA Private Enterprise Number.
  void setOemidPen(int pen) => _map[258] = pen;

  /// The product or board model identifier (key 259), opaque bytes as the
  /// manufacturer defines them.
  Uint8List? get hwModel => _asBytes(_map[259]);
  set hwModel(Uint8List? value) => _set(259, value);

  /// The hardware revision identifier (key 260).
  ///
  /// Stored as a 1-element CBOR array per RFC 9711 Section 4.2.5. The optional
  /// version scheme is not supported.
  String? get hwVersion {
    final v = _map[260];
    if (v is List && v.isNotEmpty) return v[0] as String?;
    return null;
  }

  set hwVersion(String? value) => _set(260, value != null ? [value] : null);

  /// The number of seconds since the last boot (key 261).
  int? get uptime => _map[261] as int?;
  set uptime(int? value) => _set(261, value);

  /// Whether every boot stage was OEM authorized, meaning secure boot passed
  /// (key 262).
  bool? get oemBoot => _map[262] as bool?;
  set oemBoot(bool? value) => _set(262, value);

  /// The state of the device's debug facilities at attestation time (key 263).
  ///
  /// The getter returns null if the claim is absent or holds an unknown state.
  DebugState? get debugStatus {
    final v = _map[263];
    if (v is! int || v < 0 || v > 4) return null;
    return DebugState.values[v];
  }

  set debugStatus(DebugState? value) => _set(263, value?.index);

  /// The number of times the device has booted, a monotonic counter (key 267).
  int? get bootCount => _map[267] as int?;
  set bootCount(int? value) => _set(267, value);

  /// A random value unique to the current boot cycle (key 268), the same in
  /// every token of one boot cycle.
  Uint8List? get bootSeed => _asBytes(_map[268]);
  set bootSeed(Uint8List? value) => _set(268, value);

  /// The name of the firmware or software running on the device (key 270).
  String? get swName => _map[270] as String?;
  set swName(String? value) => _set(270, value);

  /// The software version identifier (key 271).
  ///
  /// Stored as a 1-element CBOR array per RFC 9711 Section 4.2.7. The optional
  /// version scheme is not supported.
  String? get swVersion {
    final v = _map[271];
    if (v is List && v.isNotEmpty) return v[0] as String?;
    return null;
  }

  set swVersion(String? value) => _set(271, value != null ? [value] : null);

  /// The purpose the token was issued for (key 275).
  ///
  /// The getter returns null if the claim is absent or holds an unknown use.
  IntendedUse? get intendedUse {
    final v = _map[275];
    if (v is! int || v < 1 || v > 5) return null;
    return IntendedUse.values[v - 1];
  }

  set intendedUse(IntendedUse? value) =>
      _set(275, value != null ? value.index + 1 : null);

  /// Gets a custom claim by its integer key, or null if absent.
  Object? operator [](int key) => _map[key];

  /// Sets a custom claim by its integer key, or removes it if [value] is null.
  void operator []=(int key, Object? value) => _set(key, value);

  void _set(int key, Object? value) {
    if (value != null) {
      _map[key] = value;
    } else {
      _map.remove(key);
    }
  }

  /// Encodes the claims to CBOR bytes, keys in deterministic order.
  Uint8List _encode() {
    final keys = _map.keys.toList()..sort(_compareKeys);
    return Uint8List.fromList(
      cbor.cbor.encode({for (final key in keys) key: _map[key]}),
    );
  }

  /// Orders integer map keys the way deterministic CBOR sorts their encodings,
  /// non-negative keys ascending, then negative keys from -1 downward.
  static int _compareKeys(int a, int b) {
    if ((a < 0) != (b < 0)) {
      return a < 0 ? 1 : -1;
    }
    return a < 0 ? b.compareTo(a) : a.compareTo(b);
  }

  /// Decodes claims from CBOR bytes.
  static Claims _decode(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes);
    if (decoded is! Map) {
      throw FormatException('CWT claims must be a CBOR map');
    }
    final map = <int, Object?>{};
    for (final entry in decoded.entries) {
      if (entry.key is! int) {
        throw FormatException(
          'CWT claim key must be an integer, got ${entry.key.runtimeType}',
        );
      }
      map[entry.key as int] = entry.value;
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

  /// All debug has been disabled since boot. End users and developers cannot
  /// re-enable it, but the manufacturer identified by `oemid` may do so. The
  /// `oemid` claim must be present; the application must enforce this.
  disabledPermanently,

  /// All debug facilities are permanently disabled, including manufacturer
  /// facilities; none can be re-enabled.
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
/// - [domain]: Application domain for separating protocol purposes
///
/// Throws if the claims do not encode into the supported CBOR subset.
Uint8List issue({
  required Claims claims,
  required xdsa.SecretKey signer,
  required Uint8List domain,
}) => ffi.cwtIssue(
  claimsCbor: claims._encode(),
  signer: signer.inner,
  domain: domain,
);

/// Verifies a CWT's COSE signature and temporal validity, then returns the
/// decoded claims.
///
/// When [now] is provided, temporal claims are validated. The nbf claim (key
/// 5, [Claims.notBefore]) must be present and `nbf <= now`, and if the exp
/// claim (key 4, [Claims.expiration]) is present then `now < exp`. When [now]
/// is null, temporal validation is skipped entirely.
///
/// The COSE signature timestamp is not checked; temporal validity comes from
/// the CWT claims. Successful verification does not establish issuer trust,
/// enforce an audience, evaluate attestation policy or EAT claim
/// relationships, or prove possession of a Confirm key. The application must
/// perform those checks.
///
/// - [token]: The serialized CWT
/// - [verifier]: The xDSA public key to verify against
/// - [domain]: Application domain for separating protocol purposes
/// - [now]: Unix timestamp in seconds for temporal validation (null to skip)
///
/// Throws if [now] is negative, if the token is malformed, was signed by
/// another key or does not verify, or if it fails the temporal checks.
Claims verify({
  required Uint8List token,
  required xdsa.PublicKey verifier,
  required Uint8List domain,
  int? now,
}) {
  if (now != null && now < 0) {
    throw ArgumentError.value(
      now,
      'now',
      'must be a non-negative Unix timestamp',
    );
  }
  return Claims._decode(
    ffi.cwtVerify(
      token: token,
      verifier: verifier.inner,
      domain: domain,
      now: now != null ? BigInt.from(now) : null,
    ),
  );
}

/// Extracts the signer's fingerprint from a CWT without verifying.
///
/// The returned data is unauthenticated. Use this to look up the appropriate
/// verification key before calling [verify]. Throws if the token is malformed.
xdsa.Fingerprint signer({required Uint8List token}) =>
    xdsa.FingerprintInternal.wrap(ffi.cwtSigner(token: token));

/// Extracts claims from a CWT without verifying the signature.
///
/// The claims are unauthenticated and must not be trusted until verified with
/// [verify]. Use [signer] to extract the signer's fingerprint for key lookup.
/// The single case for this method is self-signed key discovery.
///
/// Throws if the token is malformed.
Claims peek({required Uint8List token}) =>
    Claims._decode(ffi.cwtPeek(token: token));
