.PHONY: generate format version

format:
	fvm dart format . --language-version=3.9
	cargo fmt --all --manifest-path rust/Cargo.toml

generate:
	flutter_rust_bridge_codegen generate
	fvm dart run scripts/prefix_frb_symbols.dart
	fvm dart format . --language-version=3.9
	cargo fmt --all --manifest-path rust/Cargo.toml

version:
ifndef VERSION
	$(error VERSION is not set. Usage: make version VERSION=x.y.z)
endif
	@echo "Setting version to $(VERSION)"
	sed -i '' 's/^version: .*/version: $(VERSION)/' pubspec.yaml
	sed -i '' "s/^version = .*/version = \"$(VERSION)\"/" rust/Cargo.toml
	sed -i '' "s/s\.version .*/s.version          = '$(VERSION)'/" ios/darkbio_crypto.podspec
	sed -i '' "s/s\.version .*/s.version          = '$(VERSION)'/" macos/darkbio_crypto.podspec
