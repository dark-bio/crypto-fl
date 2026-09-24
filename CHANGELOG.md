# Changelog

## 0.19.2

- Mark the test vectors as false secrets, so pub.dev accepts the package

## 0.19.1

- Wrap darkbio-crypto v0.19.1
- Document every public API, with an example per library
- Sort CWT claim keys, so claims can be set in any order
- Compare key fingerprints by their bytes
- Check COSE payloads and CWT claims against the CBOR subset when reading them
- Encode CBOR lists and maps of any size with a definite length
- Decode CWT claims into the types they are set with, so they issue again unchanged
- Reject a negative COSE drift and out-of-range `argon2`, `hkdf` and `rand` integers
- Reject text holding a lone surrogate, instead of encoding it as U+FFFD
- Add `dispose()` to secret keys and HPKE contexts, wiping them from memory on demand
- Name the native library correctly in the macOS, Linux and Windows source builds
- Add a Dart test suite with the shared test vectors, run in CI
- Refresh dependency locks

## 0.18.0

- Wrap darkbio-crypto v0.18.0
- Refresh dependency locks

## 0.17.2

- Wrap darkbio-crypto v0.17.2
- Refresh dependency locks and workflow actions

## 0.17.1

- Wrap darkbio-crypto v0.17.1

## 0.17.0

- Wrap darkbio-crypto v0.17.0
- Bump flutter_rust_bridge to 2.13.0
- Refresh vendored cargokit (Android 16KB page size support)

## 0.16.0

- Wrap darkbio-crypto v0.16.0
- Remove X.509 certificate APIs (xDSA/xHPKE `fromCertDer`/`fromCertPem`/`toCertDer`/`toCertPem`)

## 0.15.0

- Wrap darkbio-crypto v0.15.0

## 0.13.1

- Fix CWT verification issue due to CBOR package bug

## 0.13.0

- Wrap darkbio-crypto v0.13.0
- Add xHPKE Sender/Receiver multi-message encryption contexts
- Add CWT (CBOR Web Token) support with typed CWT and EAT claims

## 0.11.11

- Wrap darkbio-crypto v0.11.11
- Bring version number into sync with ecosystem

## 0.3.2

- Fix build script that was referencing old podfile

## 0.3.1

- Wrap darkbio-crypto v0.11.9

## 0.3.0

- Expose CBOR verification, enforce it through COSE
- Wrap darkbio-crypto v0.11.7

## 0.2.1

- Fix iOS symbol stripping in published package
- Wrap darkbio-crypto v0.11.6

## 0.2.0

- Patch binary symbol table on iOS/macOS for parallel loading
- Wrap darkbio-crypto v0.11.5 to fix an upstream version issue

## 0.1.4

- Remove stale duplicate FRB generated code

## 0.1.3

- Fix iOS bundle to load statically

## 0.1.2

- Create whole outer wrapper for cleaner docs

## 0.1.1

- Version bump for pub.dev publishing

## 0.1.0

- Test release wrapping the darkbio-crypto v0.11.4 Rust crate
