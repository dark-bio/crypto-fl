#!/usr/bin/env dart
// Patches FRB generated Dart code to use prefixed symbol lookups.
// This avoids C symbol clashes when the app also uses flutter_rust_bridge.
//
// The Rust symbols are renamed post-build by scripts/prefix_frb_symbols.sh
// using llvm-objcopy.

import 'dart:io';

const prefix = 'darkbio_crypto_';

void main() {
  patchDart();
  print('Done. FRB Dart code patched to use prefixed symbols.');
}

void patchDart() {
  final file = File('lib/src/generated/frb_generated.dart');
  if (!file.existsSync()) {
    stderr.writeln('Warning: ${file.path} not found, skipping Dart patch');
    return;
  }

  var content = file.readAsStringSync();

  // Add import for our prefixed binding helper
  if (!content.contains('frb_prefixed_binding.dart')) {
    content = content.replaceFirst(
      "import 'frb_generated.io.dart'",
      "import '../frb_prefixed_binding.dart';\nimport 'frb_generated.io.dart'",
    );
  }

  // Replace the init() method to use our overridden initImpl with prefixed binding.
  if (!content.contains('createPrefixedFrbRustBinding')) {
    content = content.replaceFirst(
      '''  /// Initialize flutter_rust_bridge
  static Future<void> init({
    RustLibApi? api,
    BaseHandler? handler,
    ExternalLibrary? externalLibrary,
    bool forceSameCodegenVersion = true,
  }) async {
    await instance.initImpl(
      api: api,
      handler: handler,
      externalLibrary: externalLibrary,
      forceSameCodegenVersion: forceSameCodegenVersion,
    );
  }''',
      '''  /// Initialize flutter_rust_bridge
  static Future<void> init({
    RustLibApi? api,
    BaseHandler? handler,
    ExternalLibrary? externalLibrary,
    bool forceSameCodegenVersion = true,
  }) async {
    await instance.initImpl(
      api: api,
      handler: handler,
      externalLibrary: externalLibrary,
      forceSameCodegenVersion: forceSameCodegenVersion,
    );
  }

  /// Override initImpl to use prefixed symbol lookups.
  /// This avoids C symbol clashes when the app uses another FRB package.
  @override
  Future<void> initImpl({
    RustLibApi? api,
    BaseHandler? handler,
    ExternalLibrary? externalLibrary,
    bool forceSameCodegenVersion = true,
  }) async {
    final lib = externalLibrary ?? await loadExternalLibrary(kDefaultExternalLibraryLoaderConfig);
    final h = handler ?? BaseHandler();
    final binding = createPrefixedFrbRustBinding(lib);

    // Sanity check with our prefixed binding
    if (forceSameCodegenVersion) {
      final rustHash = binding.getRustContentHash();
      final dartHash = rustContentHash;
      if (rustHash != dartHash) {
        throw StateError(
          'Content hash on Dart side (\$dartHash) '
          'is different from Rust side (\$rustHash), indicating out-of-sync code. '
          'This may happen when the Dart code is hot-restarted without recompiling Rust.',
        );
      }
    }

    // Initialize the binding
    binding.storeDartPostCObject();
    binding.initFrbDartApiDl();
    binding.initShutdownWatcher();

    final portManager = PortManager(binding, h);
    final a = api ?? RustLibApiImpl(
      handler: h,
      wire: RustLibWire.fromExternalLibrary(lib),
      generalizedFrbRustBinding: binding,
      portManager: portManager,
    );

    // Use initMockImpl to set state without parent's sanity check,
    // then manually run executeRustInitializers.
    initMockImpl(api: a);
    await executeRustInitializers();
  }''',
    );
  }

  file.writeAsStringSync(content);
  print('Patched: ${file.path}');
}
