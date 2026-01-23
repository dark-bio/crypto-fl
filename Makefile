.PHONY: generate format

format:
	fvm dart format . --language-version=3.9
	cargo fmt --all --manifest-path rust/Cargo.toml

generate:
	flutter_rust_bridge_codegen generate
	fvm dart format . --language-version=3.9
	cargo fmt --all --manifest-path rust/Cargo.toml
