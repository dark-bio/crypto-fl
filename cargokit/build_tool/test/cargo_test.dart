/// This is copied from Cargokit (which is the official way to use it currently)
/// Details: https://fzyzcjy.github.io/flutter_rust_bridge/manual/integrate/builtin

import 'package:build_tool/src/cargo.dart';
import 'package:test/test.dart';

final _cargoToml = """
[workspace]

[profile.release]
lto = true
panic = "abort"
opt-level = "z"
# strip = "symbols"

[package]
name = "super_native_extensions"
version = "0.1.0"
edition = "2021"
resolver = "2"

[lib]
crate-type = ["cdylib", "staticlib"]
""";

void main() {
  test('parseCargoToml', () {
    final info = CrateInfo.parseManifest(_cargoToml);
    expect(info.packageName, 'super_native_extensions');
  });
}
