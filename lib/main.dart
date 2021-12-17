
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
  //static const EventChannel eventChannel =
  //EventChannel('samples.flutter.io/charging');

  String _batteryLevel = 'Battery level: unknown.';
  String _chargingStatus = 'Battery status: unknown.';
  String _returnString = 'Return string: unknown';

  Future<void> _getCryptString() async {
    String returnString;
    final arguments = {'name' : 'test name',
      'gender' : 'male'};
    try {
      //final int? result = await methodChannel.invokeMethod('getBatteryLevel');
      final String result = await methodChannel.invokeMethod('getCryptString', arguments);
      returnString = 'ReturnString: $result.';
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
    });
  }

  Future<void> _getReturnString() async {
    String returnString;
    final arguments = {'name' : 'test name',
      'gender' : 'male'};
    try {
      //final int? result = await methodChannel.invokeMethod('getBatteryLevel');
      final String result = await methodChannel.invokeMethod('getReturnString', arguments);
      returnString = 'ReturnString: $result.';
    } on PlatformException {
      returnString = 'Failed to get return string.';
    }
    setState(() {
      _returnString = returnString;
    });
  }


  Future<void> _getBatteryLevel() async {
    String batteryLevel;
    final arguments = {'name' : 'test name'}; // new
    try {
      //final int? result = await methodChannel.invokeMethod('getBatteryLevel');
      final String result = await methodChannel.invokeMethod('getBatteryLevel', arguments);
      batteryLevel = 'Battery level: $result%.';
    } on PlatformException {
      batteryLevel = 'Failed to get battery level.';
    }
    setState(() {
      _batteryLevel = batteryLevel;
    });
  }

  @override
  void initState() {
    super.initState();
    //eventChannel.receiveBroadcastStream().listen(_onEvent, onError: _onError);
  }
/*
  void _onEvent(Object? event) {
    setState(() {
      _chargingStatus =
      "Battery status: ${event == 'charging' ? '' : 'dis'}charging.";
    });
  }
  void _onError(Object error) {
    setState(() {
      _chargingStatus = 'Battery status: unknown.';
    });
  }
*/

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
                  //onPressed: _getBatteryLevel,
                  //onPressed: _getReturnString,
                  onPressed: _getCryptString,
                  child: const Text('Refresh'),
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
