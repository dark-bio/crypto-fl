// Prefixed FRB binding to avoid symbol clashes with other FRB packages.
// This wraps GeneralizedFrbRustBinding to look up prefixed symbol names.
//
// Symbol prefixing is only needed on Apple platforms (iOS/macOS) where static
// linking is used. On other platforms (Android/Linux/Windows), dynamic linking
// isolates symbols per library, so no prefixing is needed.

// ignore_for_file: implementation_imports, invalid_use_of_internal_member

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_rust_bridge/src/ffigen_generated/multi_package.dart';
import 'package:flutter_rust_bridge/src/generalized_frb_rust_binding/_io.dart'
    if (dart.library.js_interop) 'package:flutter_rust_bridge/src/generalized_frb_rust_binding/_web.dart';
import 'package:flutter_rust_bridge/src/platform_types/platform_types.dart';

export 'package:flutter_rust_bridge/src/main_components/port_manager.dart'
    show PortManager;

/// Whether to use prefixed symbol lookups.
/// Only needed on Apple platforms where static linking causes symbol clashes.
final bool _usePrefixedSymbols = Platform.isIOS || Platform.isMacOS;

const String _prefix = 'darkbio_crypto_';

/// All FRB symbols that need prefixed lookup.
/// These symbols are renamed post-build using llvm-objcopy
/// (see scripts/prefix_frb_symbols.sh).
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

ffi.Pointer<T> _prefixedLookup<T extends ffi.NativeType>(
  ffi.DynamicLibrary lib,
  String symbolName,
) {
  final name = _usePrefixedSymbols && _symbolsToPrefix.contains(symbolName)
      ? '$_prefix$symbolName'
      : symbolName;
  return lib.lookup<T>(name);
}

/// Creates a GeneralizedFrbRustBinding that uses prefixed symbol lookups
/// on Apple platforms, or standard lookups on other platforms.
GeneralizedFrbRustBinding createPrefixedFrbRustBinding(
  ExternalLibrary externalLibrary,
) {
  if (!_usePrefixedSymbols) {
    // On non-Apple platforms, use standard binding (no symbol clashes)
    return GeneralizedFrbRustBinding(externalLibrary);
  }
  return _PrefixedGeneralizedFrbRustBinding(externalLibrary);
}

class _PrefixedGeneralizedFrbRustBinding extends GeneralizedFrbRustBinding {
  final ffi.DynamicLibrary _lib;
  late final MultiPackageCBinding _prefixedBinding;

  /// Static shutdown watcher for our prefixed binding.
  static _ShutdownWatcherPrefixed? _prefixedShutdownWatcher;

  _PrefixedGeneralizedFrbRustBinding(super.externalLibrary)
    : _lib = externalLibrary.ffiDynamicLibrary {
    _prefixedBinding = MultiPackageCBinding.fromLookup(
      <T extends ffi.NativeType>(String name) => _prefixedLookup<T>(_lib, name),
    );
  }

  // ===========================================================================
  // Core dispatcher methods
  // ===========================================================================

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

  // ===========================================================================
  // FFI binding methods
  // ===========================================================================

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

  // ===========================================================================
  // Rust vec methods
  // ===========================================================================

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

  // ===========================================================================
  // Dart opaque methods
  // ===========================================================================

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

/// Shutdown watcher for prefixed binding.
final class _ShutdownWatcherPrefixed implements ffi.Finalizable {
  final ffi.NativeFinalizer _finalizer;

  _ShutdownWatcherPrefixed(ffi.Pointer<ffi.NativeFinalizerFunction> callback)
    : _finalizer = ffi.NativeFinalizer(callback) {
    _finalizer.attach(this, ffi.Pointer.fromAddress(0));
  }
}
