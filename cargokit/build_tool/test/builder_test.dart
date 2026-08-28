/// This is copied from Cargokit (which is the official way to use it currently)
/// Details: https://fzyzcjy.github.io/flutter_rust_bridge/manual/integrate/builtin

import 'package:build_tool/src/builder.dart';
import 'package:test/test.dart';

void main() {
  test('parseBuildConfiguration', () {
    var b = BuildEnvironment.parseBuildConfiguration('debug');
    expect(b, BuildConfiguration.debug);

    b = BuildEnvironment.parseBuildConfiguration('profile');
    expect(b, BuildConfiguration.profile);

    b = BuildEnvironment.parseBuildConfiguration('release');
    expect(b, BuildConfiguration.release);

    b = BuildEnvironment.parseBuildConfiguration('debug-dev');
    expect(b, BuildConfiguration.debug);

    b = BuildEnvironment.parseBuildConfiguration('profile');
    expect(b, BuildConfiguration.profile);

    b = BuildEnvironment.parseBuildConfiguration('profile-prod');
    expect(b, BuildConfiguration.profile);

    // fallback to release
    b = BuildEnvironment.parseBuildConfiguration('unknown');
    expect(b, BuildConfiguration.release);
  });
}
