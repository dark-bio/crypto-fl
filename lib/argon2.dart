/// Argon2id cryptography wrappers and parametrization.
///
/// https://datatracker.ietf.org/doc/html/rfc9106
library;

import 'dart:typed_data';

import 'src/generated/api/argon2.dart' as ffi;

/// Derives a key from the password, salt, and cost parameters using Argon2id
/// returning a byte array that can be used as a cryptographic key. The CPU
/// cost and parallelism degree must be greater than zero.
///
/// For example, you can get a derived key for e.g. AES-256 (which needs a
/// 32-byte key) by doing:
///
/// ```dart
/// final key = argon2.key(password: password, salt: salt, time: 1, memory: 64*1024, threads: 4);
/// ```
///
/// [RFC 9106 Section 7.4](https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4)
/// recommends time=1, and memory=2048*1024 as a sensible number. If using that
/// amount of memory (2GB) is not possible in some contexts then the time
/// parameter can be increased to compensate.
///
/// The [time] parameter specifies the number of passes over the memory and the
/// [memory] parameter specifies the size of the memory in KiB. The number of
/// [threads] can be adjusted to the numbers of available CPUs. The cost
/// parameters should be increased as memory latency and CPU parallelism
/// increases. Remember to get a good random salt.
Uint8List key({
  required Uint8List password,
  required Uint8List salt,
  int time = 3,
  int memory = 65536,
  int threads = 4,
  int length = 32,
}) => ffi.argon2Key(
  password: password,
  salt: salt,
  time: time,
  memory: memory,
  threads: threads,
  keyLength: BigInt.from(length),
);
