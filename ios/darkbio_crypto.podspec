#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint darkbio_crypto.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'darkbio_crypto'
  s.version          = '0.3.2'
  s.summary          = 'Cryptography wrappers and primitives'
  s.homepage         = 'https://github.com/dark-bio/crypto-fl'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Dark Bio AG' => 'peter@dark.bio' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'
  s.swift_version = '5.0'

  s.script_phases = [
    {
      :name => 'Build Rust library',
      :script => 'export CONFIGURATION=Release; sh "$PODS_TARGET_SRCROOT/../cargokit/build_pod.sh" ../rust darkbio_crypto_ffi',
      :execution_position => :before_compile,
      :input_files => ['${BUILT_PRODUCTS_DIR}/cargokit_phony'],
      :output_files => ["${BUILT_PRODUCTS_DIR}/libdarkbio_crypto_ffi.a"],
    },
    {
      :name => 'Prefix FRB symbols',
      :script => 'sh "$PODS_TARGET_SRCROOT/../scripts/prefix_frb_symbols.sh" "${BUILT_PRODUCTS_DIR}/libdarkbio_crypto_ffi.a"',
      :execution_position => :before_compile,
      :input_files => ["${BUILT_PRODUCTS_DIR}/libdarkbio_crypto_ffi.a"],
      :output_files => ["${BUILT_PRODUCTS_DIR}/libdarkbio_crypto_ffi.a.prefixed"],
    },
  ]
  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386',
    'OTHER_LDFLAGS' => '-force_load ${BUILT_PRODUCTS_DIR}/libdarkbio_crypto_ffi.a',
  }
end
