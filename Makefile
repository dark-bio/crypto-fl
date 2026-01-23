.PHONY: generate

generate:
	flutter_rust_bridge_codegen generate
	fvm dart format .
	cargo fmt --all --manifest-path rust/Cargo.toml
