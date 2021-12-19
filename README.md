# platform_channel_crypt

AES GCM encryption works in iOS using CommonCrypto and SwCrypt

https://github.com/soyersoyer/SwCrypt

Hinweis: enthält Änderungen wegen UnsafeMutuableBytes und UnsafePointer unter Swift 5

neu 19.12.2021:
Diese Version basiert NICHT auf dem offiziell Repository mit Versionsstand 5.1.4,
sondern auf einem Pull Request https://github.com/soyersoyer/SwCrypt/pull/65

Version beinhaltet nun neben dem iOS auch den Android native code

WICHTIG: beide Versionen sind noch nicht kompatibel, da die Zahl der Iterationen noch fehlt 
(in iOS im Ausgabestring enthalten, bei Android noch nicht)

alt: 
Diese Version basiert NICHT auf dem offiziell Repository mit Versionsstand 5.1.4,
 sondern auf einem Pull Request https://github.com/soyersoyer/SwCrypt/pull/51





Funktioniert unter iPhone5 + iOS 15

https://stackoverflow.com/questions/34855741/how-to-encrypt-using-aes-gcm-on-ios/36634956#36634956

https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60074/include/CommonCryptorSPI.h

Obj-C https://stackoverflow.com/questions/38913437/aes-128-gcm-objective-c-osx/39777143#39777143

Obj-C https://github.com/indisoluble/AesGcm

CommonCrypto: Let's back to CommonCrypto file,Apple have released it's source code in 
 https://opensource.apple.com/source/

```plaintext 
The old one:
_ = data.withUnsafeMutableBytes { (bytes: UnsafeMutablePointer<UInt8>) in
        memcpy((ioData.pointee.mBuffers.mData?.assumingMemoryBound(to: UInt8.self))!, bytes, dataCount)
    }

The new one:
_ = data.withUnsafeMutableBytes { (rawMutableBufferPointer) in
        let bufferPointer = rawMutableBufferPointer.bindMemory(to: UInt8.self)
        if let address = bufferPointer.baseAddress{
            memcpy((ioData.pointee.mBuffers.mData?.assumingMemoryBound(to: UInt8.self))!, address, dataCount)
        }
    }

my old code:
var data = Data(count: size)
data.withUnsafeMutableBytes { dataBytes in
  _ = CCRandomGenerateBytes!(dataBytes, size)
}
return data

my new code:
var data = Data(count: size)
data.withUnsafeMutableBytes { dataBytes in
  _ = CCRandomGenerateBytes!(dataBytes, size)
}
return data


```



code based on https://docs.flutter.dev/development/platform-integration/platform-channels?tab=type-mappings-java-tab

https://github.com/flutter/flutter/tree/master/examples/platform_channel

https://docs.flutter.dev/development/platform-integration/platform-channels?tab=type-mappings-java-tab

swift: https://github.com/flutter/flutter/tree/master/examples/platform_channel_swift

Johannes Milke Android: https://www.youtube.com/watch?v=j0cy_Z6IG_c

Johannes Milke SWIFT: https://www.youtube.com/watch?v=EHQTdB2qenU



A new Flutter project.

## Getting Started

This project is a starting point for a Flutter application.

A few resources to get you started if this is your first Flutter project:

- [Lab: Write your first Flutter app](https://flutter.dev/docs/get-started/codelab)
- [Cookbook: Useful Flutter samples](https://flutter.dev/docs/cookbook)

For help getting started with Flutter, view our
[online documentation](https://flutter.dev/docs), which offers tutorials,
samples, guidance on mobile development, and a full API reference.
