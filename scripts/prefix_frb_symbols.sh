#!/bin/bash
# Rename FRB symbols in static libraries to use "darkbio_crypto_" prefix.
# This prevents symbol clashes when multiple FRB-based packages are statically linked.
#
# Uses llvm-objcopy --redefine-sym to rename symbols and update all references.
#
# Usage: ./prefix_frb_symbols.sh [lib_path]
# Example: ./prefix_frb_symbols.sh rust/target/aarch64-apple-ios/release/libdarkbio_crypto_ffi.a

set -e

PREFIX="darkbio_crypto_"

# FRB symbols that need to be renamed (without leading underscore - objcopy adds it)
FRB_SYMBOLS=(
    # Core dispatcher symbols
    "frb_get_rust_content_hash"
    "frb_pde_ffi_dispatcher_primary"
    "frb_pde_ffi_dispatcher_sync"
    "frb_dart_fn_deliver_output"
    # FFI binding symbols
    "frb_init_frb_dart_api_dl"
    "frb_free_wire_sync_rust2dart_dco"
    "frb_free_wire_sync_rust2dart_sse"
    "frb_create_shutdown_callback"
    # Rust vec symbols
    "frb_rust_vec_u8_new"
    "frb_rust_vec_u8_resize"
    "frb_rust_vec_u8_free"
    # Dart opaque symbols
    "frb_dart_opaque_dart2rust_encode"
    "frb_dart_opaque_rust2dart_decode"
    "frb_dart_opaque_drop_thread_box_persistent_handle"
    # allo_isolate symbol
    "store_dart_post_cobject"
)

# Find llvm-objcopy
find_objcopy() {
    # Try Homebrew LLVM first
    if command -v brew &>/dev/null; then
        local llvm_prefix="$(brew --prefix llvm 2>/dev/null || true)"
        if [ -n "$llvm_prefix" ] && [ -x "$llvm_prefix/bin/llvm-objcopy" ]; then
            echo "$llvm_prefix/bin/llvm-objcopy"
            return 0
        fi
    fi
    
    # Try PATH
    if command -v llvm-objcopy &>/dev/null; then
        echo "llvm-objcopy"
        return 0
    fi
    
    # Try common Xcode/CommandLineTools locations
    for path in \
        "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objcopy" \
        "/Library/Developer/CommandLineTools/usr/bin/llvm-objcopy"; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    echo ""
    return 1
}

process_static_lib() {
    local lib_path="$1"
    local objcopy="$2"
    
    if [ ! -f "$lib_path" ]; then
        echo "Error: $lib_path not found"
        return 1
    fi
    
    echo "Processing: $lib_path"
    
    # Build redefine-sym arguments
    # Mach-O symbols have leading underscore
    local redefine_args=()
    for sym in "${FRB_SYMBOLS[@]}"; do
        redefine_args+=("--redefine-sym=_${sym}=_${PREFIX}${sym}")
    done
    
    # Process in-place
    "$objcopy" "${redefine_args[@]}" "$lib_path"
    
    # Verify
    local prefixed_count=$(nm -gU "$lib_path" 2>/dev/null | grep -c "_${PREFIX}" || echo "0")
    echo "  Done: $prefixed_count prefixed symbols"
}

# Main
OBJCOPY=$(find_objcopy)
if [ -z "$OBJCOPY" ]; then
    echo "Error: llvm-objcopy not found"
    echo "Install with: brew install llvm"
    exit 1
fi

echo "Using: $OBJCOPY"

# Find script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_DIR="$SCRIPT_DIR/../rust"

if [ $# -ge 1 ]; then
    # Process specified library
    process_static_lib "$1" "$OBJCOPY"
else
    # Process all iOS static libraries
    echo "Processing all iOS static libraries..."
    cd "$RUST_DIR"
    for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
        for profile in debug release; do
            lib_path="target/${target}/${profile}/libdarkbio_crypto_ffi.a"
            if [ -f "$lib_path" ]; then
                process_static_lib "$lib_path" "$OBJCOPY"
            fi
        done
    done
fi

echo "Symbol prefixing complete."
