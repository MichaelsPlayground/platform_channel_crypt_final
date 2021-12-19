
// Copyright 2014 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

class PlatformChannel extends StatefulWidget {
  const PlatformChannel({Key? key}) : super(key: key);

  @override
  State<PlatformChannel> createState() => _PlatformChannelState();
}

class _PlatformChannelState extends State<PlatformChannel> {
  static const MethodChannel methodChannel =
  MethodChannel('samples.flutter.io/strings');

  String _returnString = 'Return string: unknown';

  Future<void> _getCryptString() async {
    String returnString;
    final arguments = {'name' : 'test name',
      'gender' : 'male'};
    try {
      final String result = await methodChannel.invokeMethod('getCryptString', arguments);
      returnString = 'ReturnString: $result.';
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
    });
  }

  Future<void> _getCryptEncString() async {
    String returnString;
    final arguments = {'password' : 'mein geheimes passwort',
      'iterations' : '10001',
      'plaintext' : 'Mein wichtiges Geheimnis'};
    try {
      final String result = await methodChannel.invokeMethod('getCryptEncString', arguments);
      returnString = '$result';
      print(returnString);
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
    });
  }

  Future<void> _getCryptEncStringOld() async {
    String returnString;
    final arguments = {'password' : 'mein geheimes passwort',
      'plaintext' : 'Mein wichtiges Geheimnis'};
    try {
      final String result = await methodChannel.invokeMethod('getCryptEncString', arguments);
      returnString = '$result';
      print(returnString);
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
    });
  }

  Future<void> _getCryptDecString() async {
    String returnString;
    // ios
    //_returnString = 'a1uTWRddpW24gPWvLvNUlE1ZUqfbdTOiLfJO4X5YHUo=:10001:6uOdtkH5ORQfTAeS:MdLfcw6ZS9ZMQoPTn8Vhvwxf/dRKXWyVEXKER6NCVQzZ+eBbZwQzTA==';
    //_returnString = 'a1uTWRddpW24gPWvLvNUlE1ZUqfbdTOiLfJO4X5YHUo=:6uOdtkH5ORQfTAeS:MdLfcw6ZS9ZMQoPTn8Vhvwxf/dRKXWyVEXKER6NCVQzZ+eBbZwQzTA==';
    // android
    //_returnString = 'GtI0M5LLBkQA5vztZ3LhQupPwslLMsmagnqfHCnV/a4=:DG81eBnqgBDKI+bG:kVehtaYbIoTmhA1bmiY4peb4KymN5RqgMDmokM1TRiWhAfo5Oh0I7Q==';
    final arguments = {'password' : 'mein geheimes passwort',
      'ciphertext' : _returnString};
    try {
      final String result = await methodChannel.invokeMethod('getCryptDecString', arguments);
      returnString = '$result';
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
    });
  }

  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Material(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.spaceEvenly,
        children: <Widget>[
          Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              Text('Crypt AES GCM'),
              Text(_returnString, key: const Key('Return String label')),
              Padding(
                padding: const EdgeInsets.all(16.0),
                child: ElevatedButton(
                  onPressed: _getCryptString,
                  child: const Text('Refresh'),
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(16.0),
                child: ElevatedButton(
                  onPressed: _getCryptEncString,
                  child: const Text('Enc'),
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(16.0),
                child: ElevatedButton(
                  onPressed: _getCryptDecString,
                  child: const Text('Dec'),
                ),
              ),
            ],
          ),
          //Text(_chargingStatus),
        ],
      ),
    );
  }
}

void main() {
  runApp(const MaterialApp(home: PlatformChannel()));
}
