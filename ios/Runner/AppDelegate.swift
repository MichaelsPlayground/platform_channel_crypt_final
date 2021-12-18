// Copyright 2014 The Flutter Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
import UIKit
import Flutter

import CommonCrypto
import Foundation

enum ChannelName {
  //static let battery = "samples.flutter.io/battery"
  static let charging = "samples.flutter.io/charging"
    static let strings = "samples.flutter.io/strings"
}

enum BatteryState {
  static let charging = "charging"
  static let discharging = "discharging"
}

enum MyFlutterErrorCode {
  static let unavailable = "UNAVAILABLE"
}

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate{


  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {



    let controller = window?.rootViewController as! FlutterViewController
        let stringChannel = FlutterMethodChannel(name: ChannelName.strings,
                                                  binaryMessenger: controller.binaryMessenger)

        GeneratedPluginRegistrant.register(with: self)



        /*
        let stringsChannel = FlutterEventChannel(name: ChannelName.strings,
                                                 binaryMessenger: controller.binaryMessenger)
        stringsChannel.setMethodCallHandler({
            (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in switch call.method{
            case "getReturnString":
                guard let args = call.arguments as? [String: String] else {return}
                let name = args["name"]!
                //result("\(name) says on IOS10 \(self.receiveBatteryLevel2())")
                result("\(name) says on IOS10 gender")
            default:
                result(FlutterMethodNotImplemented)
            }

        })
        */


    // new Johannes Milke
        //let batteryChannel = FlutterMethodChannel(name: ChannelName.battery,
        stringChannel.setMethodCallHandler({
            (call: FlutterMethodCall, result: @escaping FlutterResult) -> Void in switch call.method{
            case "getBatteryLevel":
                guard let args = call.arguments as? [String: String] else {return}
                let name = args["name"]!
                result("\(name) ended")
            case "getReturnString":
                guard let args = call.arguments as? [String: String] else {return}
                let name = args["name"]!
                let gender = args["gender"]!
                result("\(name) is on IOS10 \(gender)")

            case "getCryptEncString":
                guard let args = call.arguments as? [String: String] else {return}
                let password = args["password"]!
                let plaintext : String? = args["plaintext"]
                if (plaintext == nil) {result("")}

                print("PBKDF2 SHA256 using CommonCrypto")
                //let password     = password
                let salt         = CC.generateRandom(32)
                let keyByteCount = 32 // AES256
                let rounds       = 100001
                let encryptionKey = pbkdf2(password: password, saltData: salt, keyByteCount: keyByteCount, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
                print("encryptionKey: " + encryptionKey!.hexEncodedString())

                print()
                print("AES GCM")
                let aesKey = encryptionKey!
                //let aesKey = CC.generateRandom(32)
                let iv = CC.generateRandom(12)
                let plainData = plaintext!.data(using: String.Encoding.utf8)!
                print("p: " + plainData.hexEncodedString())
                let testData = "This is a test string".data(using: String.Encoding.utf8)!
                //let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: testData, aData: Data(), key: aesKey, iv: iv, tagLength: 8)
                let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: plainData, aData: Data(), key: aesKey, iv: iv, tagLength: 16)

                print("e: " + (e?.hexEncodedString())!)
                //let d = try? CC.cryptAuth(.decrypt, blockMode: .gcm, algorithm: .aes, data: e!, aData: Data(), key: aesKey, iv: iv, tagLength: 16)
                //print("d: " + (d?.hexEncodedString())!)

                let eB64 : String = (e?.base64EncodedString())!
                let ivB64 : String = iv.base64EncodedString()
                let saltB64 : String = salt.base64EncodedString()

                let cComplete = saltB64 + ":" +
                rounds.string + ":" +
                ivB64 + ":" +
                eB64;
                print("cComplete: " + cComplete)
                result("\(cComplete)")

            case "getCryptDecString":
                            guard let args = call.arguments as? [String: String] else {return}
                            let password = args["password"]!
                            let completeCiphertext : String? = args["ciphertext"]
                            if (completeCiphertext == nil) {result("")}
                            // split ciphertext
                
                            let parts = completeCiphertext!.components(separatedBy: ":")
                            let salt = parts[0].base64Decoded
                            // let rounds = parts[1] // string to int conversion
                            let iv = parts[2].base64Decoded
                            let ciphertext = parts[3].base64Decoded

                            print("PBKDF2 SHA256 using CommonCrypto")
                            //let password     = password
                            //let salt         = CC.generateRandom(32)
                            let keyByteCount = 32 // AES256
                            let rounds       = 100001
                let encryptionKey = pbkdf2(password: password, saltData: salt!, keyByteCount: keyByteCount, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
                            print("encryptionKey: " + encryptionKey!.hexEncodedString())

                            print()
                            print("AES GCM")
                            let aesKey = encryptionKey!
                            //let aesKey = CC.generateRandom(32)
                            //let iv = CC.generateRandom(12)
                            //let plainData = plaintext!.data(using: String.Encoding.utf8)!
                            //print("p: " + plainData.hexEncodedString())
                            //let testData = "This is a test string".data(using: String.Encoding.utf8)!
                            //let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: testData, aData: Data(), key: aesKey, iv: iv, tagLength: 8)
                            //let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: plainData, aData: Data(), key: aesKey, iv: iv, tagLength: 16)

                            //print("e: " + (e?.hexEncodedString())!)
                            let d = try? CC.cryptAuth(.decrypt, blockMode: .gcm, algorithm: .aes, data: ciphertext!, aData: Data(), key: aesKey, iv: iv!, tagLength: 16)
                            //print("d: " + (d?.hexEncodedString())!)

                            //let eB64 : String = (e?.base64EncodedString())!
                            //let ivB64 : String = iv.base64EncodedString()
                            //let saltB64 : String = salt.base64EncodedString()

                            //let cComplete = saltB64 + ":" +
                            //rounds.string + ":" +
                            //ivB64 + ":" +
                            //eB64;
                            //print("cComplete: " + cComplete)
                            let decryptedtext = String(decoding: d!, as: UTF8.self)
                            result("\(decryptedtext)")

            case "getCryptString":
                guard let args = call.arguments as? [String: String] else {return}
                let name = args["name"]!
                let gender = args["gender"]!

                print("PBKDF2 SHA256 using CommonCrypto")
                let password     = "password"
                //let salt       = "saltData".data(using: String.Encoding.utf8)!
                let salt         = Data(_: [0x73, 0x61, 0x6c, 0x74, 0x44, 0x61, 0x74, 0x61])
                let keyByteCount = 32 // AES256
                let rounds       = 100001
                let encryptionKey = pbkdf2(password: password, saltData: salt, keyByteCount: keyByteCount, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds: rounds)
                print("encryptionKey: " + encryptionKey!.hexEncodedString())

                print("generate random number")
                let randomData = try! secureRandomData(count: 32)
                print("random: " + randomData.hexEncodedString())

                print()
                print("AES GCM")
                let aesKey = CC.generateRandom(32)
                let iv = CC.generateRandom(12)
                let testData = "This is a test string".data(using: String.Encoding.utf8)!
                print("p: " + testData.hexEncodedString())
                
                let e = try? CC.cryptAuth(.encrypt, blockMode: .gcm, algorithm: .aes, data: testData, aData: Data(), key: aesKey, iv: iv, tagLength: 8)
                
                print("e: " + (e?.hexEncodedString())!)
                        
                let d = try? CC.cryptAuth(.decrypt, blockMode: .gcm, algorithm: .aes, data: e!, aData: Data(), key: aesKey, iv: iv, tagLength: 8)
                        
                print("d: " + (d?.hexEncodedString())!)

                let eB64 : String = (e?.base64EncodedString())!
                let ivB64 : String = iv.base64EncodedString()
                let saltB64 : String = salt.base64EncodedString()
                
                let cComplete = saltB64 + ":" +
                rounds.string + ":" +
                ivB64 + ":" +
                eB64;
                print("cComplete: " + cComplete)
                result("\(name) encrypts SwCrypt to \(cComplete)")


            default:
                result(FlutterMethodNotImplemented)
            }

        })

        return super.application(application, didFinishLaunchingWithOptions: launchOptions)

    /* org
    let batteryChannel = FlutterMethodChannel(name: ChannelName.battery,
                                              binaryMessenger: controller.binaryMessenger)
    batteryChannel.setMethodCallHandler({
      [weak self] (call: FlutterMethodCall, result: FlutterResult) -> Void in
      guard call.method == "getBatteryLevel" else {
        result(FlutterMethodNotImplemented)
        return
      }

        // new
        //let args = call.arguments as? [String: String]
        //let name = args["name"]!
        // end new

        self?.receiveBatteryLevel(result: result)
        //self?.receiveBatteryLevel(result: "\(name) says \result")
    })
*/

/*
    let chargingChannel = FlutterEventChannel(name: ChannelName.charging,
                                              binaryMessenger: controller.binaryMessenger)
    chargingChannel.setStreamHandler(self)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
 */
  }
    
    
    
/*
    private func receiveBatteryLevel2() -> Int {
        let device = UIDevice.current
        device.isBatteryMonitoringEnabled = true
        if device.batteryState == UIDevice.BatteryState.unknown {
            return -1
        } else {
            return Int(device.batteryLevel * 100)
        }
    }

  private func receiveBatteryLevel(result: FlutterResult) {
    let device = UIDevice.current
    device.isBatteryMonitoringEnabled = true
    guard device.batteryState != .unknown  else {
      result(FlutterError(code: MyFlutterErrorCode.unavailable,
                          message: "Battery info unavailable",
                          details: nil))
      return
    }
    result(Int(device.batteryLevel * 100))
  }



  public func onListen(withArguments arguments: Any?,
                       eventSink: @escaping FlutterEventSink) -> FlutterError? {
    self.eventSink = eventSink
    UIDevice.current.isBatteryMonitoringEnabled = true
    sendBatteryStateEvent()
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(AppDelegate.onBatteryStateDidChange),
      name: UIDevice.batteryStateDidChangeNotification,
      object: nil)
    return nil
  }

  @objc private func onBatteryStateDidChange(notification: NSNotification) {
    sendBatteryStateEvent()
  }

  private func sendBatteryStateEvent() {
    guard let eventSink = eventSink else {
      return
    }

    switch UIDevice.current.batteryState {
    case .full:
      eventSink(BatteryState.charging)
    case .charging:
      eventSink(BatteryState.charging)
    case .unplugged:
      eventSink(BatteryState.discharging)
    default:
      eventSink(FlutterError(code: MyFlutterErrorCode.unavailable,
                             message: "Charging status unavailable",
                             details: nil))
    }
  }

  public func onCancel(withArguments arguments: Any?) -> FlutterError? {
    NotificationCenter.default.removeObserver(self)
    eventSink = nil
    return nil
  }
*/
}

func secureRandomData(count: Int) throws -> Data {
    var bytes = [Int8](repeating: 0, count: count)

    // Fill bytes with secure random data
    let status = SecRandomCopyBytes(
        kSecRandomDefault,
        count,
        &bytes
    )
    
    // A status of errSecSuccess indicates success
    if status == errSecSuccess {
        // Convert bytes to Data
        let data = Data(bytes: bytes, count: count)
        return data
    }
    else {
        // Handle error
        return Data(_: [0x0])
    }
}

private func pbkdf2(password: String, saltData: Data, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int) -> Data? {
    guard let passwordData = password.data(using: .utf8) else { return nil }
    var derivedKeyData = Data(repeating: 0, count: keyByteCount)
    let derivedCount = derivedKeyData.count
    let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
        let keyBuffer: UnsafeMutablePointer<UInt8> =
            derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
        return saltData.withUnsafeBytes { saltBytes -> Int32 in
            let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                password,
                passwordData.count,
                saltBuffer,
                saltData.count,
                prf,
                UInt32(rounds),
                keyBuffer,
                derivedCount)
        }
    }
    return derivationStatus == kCCSuccess ? derivedKeyData : nil
}

extension StringProtocol {
    var data: Data { Data(utf8) }
    var base64Encoded: Data { data.base64EncodedData() }
    var base64Decoded: Data? { Data(base64Encoded: string) }
}
extension LosslessStringConvertible {
    var string: String { .init(self) }
}
extension Sequence where Element == UInt8 {
    var data: Data { .init(self) }
    var base64Decoded: Data? { Data(base64Encoded: data) }
    var string: String? { String(bytes: self, encoding: .utf8) }
}

extension Data {
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

/*import UIKit
import Flutter

@UIApplicationMain
@objc class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
*/
