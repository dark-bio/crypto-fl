.PHONY: generate format build-ios prefix-frb-symbols

format:
	fvm dart format . --language-version=3.9
	cargo fmt --all --manifest-path rust/Cargo.toml

generate:
	flutter_rust_bridge_codegen generate
	fvm dart run scripts/prefix_frb_symbols.dart
	fvm dart format . --language-version=3.9
	cargo fmt --all --manifest-path rust/Cargo.toml

# Build iOS static libraries with prefixed FRB symbols to avoid clashes
build-ios:
	cd rust && cargo build --release --target aarch64-apple-ios
	cd rust && cargo build --release --target aarch64-apple-ios-sim
	./scripts/prefix_frb_symbols.sh

# Prefix FRB symbols in already-built iOS static libraries
prefix-frb-symbols:
	./scripts/prefix_frb_symbols.sh
