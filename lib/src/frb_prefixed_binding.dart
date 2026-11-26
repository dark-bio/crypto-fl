// crypto-fl: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// ignore_for_file: implementation_imports, invalid_use_of_internal_member

/// FRB symbol lookup for standalone libraries and statically linked Apple apps.
library;

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_rust_bridge/src/ffigen_generated/multi_package.dart';
import 'package:flutter_rust_bridge/src/generalized_frb_rust_binding/_io.dart'
    if (dart.library.js_interop) 'package:flutter_rust_bridge/src/generalized_frb_rust_binding/_web.dart';
import 'package:flutter_rust_bridge/src/platform_types/platform_types.dart';

export 'package:flutter_rust_bridge/src/main_components/port_manager.dart'
    show PortManager;

/// Prefix applied to shared FRB symbols in the packaged Apple archives.
const String _prefix = 'darkbio_crypto_';

/// Shared FRB C symbols renamed post-build by `scripts/prefix_frb_symbols.sh`
/// using `llvm-objcopy`.
const List<String> _symbolsToPrefix = [
  // Core dispatcher symbols
  'frb_pde_ffi_dispatcher_primary',
  'frb_pde_ffi_dispatcher_sync',
  'frb_get_rust_content_hash',
  'frb_dart_fn_deliver_output',
  // FFI binding symbols
  'frb_init_frb_dart_api_dl',
  'frb_free_wire_sync_rust2dart_dco',
  'frb_free_wire_sync_rust2dart_sse',
  'frb_create_shutdown_callback',
  // Rust vec symbols
  'frb_rust_vec_u8_new',
  'frb_rust_vec_u8_resize',
  'frb_rust_vec_u8_free',
  // Dart opaque symbols
  'frb_dart_opaque_dart2rust_encode',
  'frb_dart_opaque_rust2dart_decode',
  'frb_dart_opaque_drop_thread_box_persistent_handle',
  // allo_isolate symbol
  'store_dart_post_cobject',
];

/// Resolves shared FRB symbols under this package's prefix.
ffi.Pointer<T> _prefixedLookup<T extends ffi.NativeType>(
  ffi.DynamicLibrary lib,
  String symbolName,
) {
  final name = _symbolsToPrefix.contains(symbolName)
      ? '$_prefix$symbolName'
      : symbolName;
  return lib.lookup<T>(name);
}

/// Selects the bindings for a packaged Apple library or a standalone build.
GeneralizedFrbRustBinding createPrefixedFrbRustBinding(
  ExternalLibrary externalLibrary,
) {
  if (Platform.isIOS || Platform.isMacOS) {
    // Process-wide lookups must use our prefix when multiple plugins coexist
    final lib = externalLibrary.ffiDynamicLibrary;
    if (lib == ffi.DynamicLibrary.process() ||
        lib.providesSymbol('${_prefix}frb_get_rust_content_hash')) {
      return _PrefixedGeneralizedFrbRustBinding(externalLibrary);
    }
  }
  return GeneralizedFrbRustBinding(externalLibrary);
}

/// FRB binding that resolves shared C symbols under [_prefix].
class _PrefixedGeneralizedFrbRustBinding extends GeneralizedFrbRustBinding {
  /// Native library holding the prefixed FRB symbols.
  final ffi.DynamicLibrary _lib;

  /// Generated C symbol table bound through [_prefixedLookup].
  late final MultiPackageCBinding _prefixedBinding;

  /// Static shutdown watcher for our prefixed binding.
  static _ShutdownWatcherPrefixed? _prefixedShutdownWatcher;

  /// Creates a prefixed FRB binding backed by [externalLibrary].
  _PrefixedGeneralizedFrbRustBinding(super.externalLibrary)
    : _lib = externalLibrary.ffiDynamicLibrary {
    _prefixedBinding = MultiPackageCBinding.fromLookup(
      <T extends ffi.NativeType>(String name) => _prefixedLookup<T>(_lib, name),
    );
  }

  @override
  void storeDartPostCObject() {
    _prefixedBinding.store_dart_post_cobject(ffi.NativeApi.postCObject.cast());
  }

  @override
  void initFrbDartApiDl() {
    _prefixedBinding.frb_init_frb_dart_api_dl(
      ffi.NativeApi.initializeApiDLData,
    );
  }

  @override
  void pdeFfiDispatcherPrimary({
    required int funcId,
    required int port,
    required ffi.Pointer<ffi.Uint8> ptr,
    required int rustVecLen,
    required int dataLen,
  }) {
    _prefixedBinding.frb_pde_ffi_dispatcher_primary(
      funcId,
      port,
      ptr,
      rustVecLen,
      dataLen,
    );
  }

  @override
  WireSyncRust2DartSse pdeFfiDispatcherSync({
    required int funcId,
    required ffi.Pointer<ffi.Uint8> ptr,
    required int rustVecLen,
    required int dataLen,
  }) {
    return _prefixedBinding.frb_pde_ffi_dispatcher_sync(
      funcId,
      ptr,
      rustVecLen,
      dataLen,
    );
  }

  @override
  int getRustContentHash() {
    return _prefixedBinding.frb_get_rust_content_hash();
  }

  @override
  void freeWireSyncRust2DartDco(WireSyncRust2DartDco value) {
    _prefixedBinding.frb_free_wire_sync_rust2dart_dco(value);
  }

  @override
  void freeWireSyncRust2DartSse(WireSyncRust2DartSse value) {
    _prefixedBinding.frb_free_wire_sync_rust2dart_sse(value);
  }

  @override
  void initShutdownWatcher() {
    _prefixedShutdownWatcher ??= _ShutdownWatcherPrefixed(
      _prefixedBinding.frb_create_shutdown_callback(),
    );
  }

  @override
  ffi.Pointer<ffi.Uint8> rustVecU8New(int len) {
    return _prefixedBinding.frb_rust_vec_u8_new(len);
  }

  @override
  ffi.Pointer<ffi.Uint8> rustVecU8Resize(
    ffi.Pointer<ffi.Uint8> ptr,
    int oldLen,
    int newLen,
  ) {
    return _prefixedBinding.frb_rust_vec_u8_resize(ptr, oldLen, newLen);
  }

  @override
  void rustVecU8Free(ffi.Pointer<ffi.Uint8> ptr, int len) {
    _prefixedBinding.frb_rust_vec_u8_free(ptr, len);
  }

  @override
  ffi.Pointer<ffi.Void> dartOpaqueDart2RustEncode(
    Object object,
    int dartHandlerPort,
  ) {
    return _prefixedBinding.frb_dart_opaque_dart2rust_encode(
      object,
      dartHandlerPort,
    );
  }

  @override
  Object dartOpaqueRust2DartDecode(int ptr) {
    return _prefixedBinding.frb_dart_opaque_rust2dart_decode(ptr);
  }

  @override
  void dartOpaqueDropThreadBoxPersistentHandle(int ptr) {
    _prefixedBinding.frb_dart_opaque_drop_thread_box_persistent_handle(ptr);
  }
}

/// Shutdown watcher for the prefixed FRB binding.
final class _ShutdownWatcherPrefixed implements ffi.Finalizable {
  /// Native finalizer invoked when the Dart isolate tears down.
  final ffi.NativeFinalizer _finalizer;

  /// Attaches [callback] to run on isolate shutdown.
  _ShutdownWatcherPrefixed(ffi.Pointer<ffi.NativeFinalizerFunction> callback)
    : _finalizer = ffi.NativeFinalizer(callback) {
    _finalizer.attach(this, ffi.Pointer.fromAddress(0));
  }
}
