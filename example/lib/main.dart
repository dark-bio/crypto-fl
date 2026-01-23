import 'package:darkbio_crypto/darkbio_crypto.dart' as darkbio_crypto;
import 'package:flutter/material.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await darkbio_crypto.init();
  runApp(const MaterialApp(home: Scaffold()));
}
