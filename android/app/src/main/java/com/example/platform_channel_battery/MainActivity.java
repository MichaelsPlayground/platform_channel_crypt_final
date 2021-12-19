package com.example.platform_channel_battery;

import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

// crypto start
import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
// crypto end

import java.util.Map;

import io.flutter.embedding.android.FlutterActivity;
import io.flutter.embedding.engine.FlutterEngine;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.MethodCall;

public class MainActivity extends FlutterActivity {
    private static final String BATTERY_CHANNEL = "samples.flutter.io/battery";

    private static final String STRINGS_CHANNEL = "samples.flutter.io/strings";

    @Override
    public void configureFlutterEngine(@NonNull FlutterEngine flutterEngine) {

        new MethodChannel(flutterEngine.getDartExecutor(), STRINGS_CHANNEL).setMethodCallHandler(
                new MethodCallHandler() {
                    @RequiresApi(api = VERSION_CODES.KITKAT)
                    @Override
                    public void onMethodCall(MethodCall call, Result result) {
                        String callMethod = call.method;
                        Map<String, String> arguments = call.arguments();
                        switch(callMethod) {
                            case "getCryptEncString":
                                String password1 = arguments.get("password");
                                String iterations1 = arguments.get("iterations");
                                String plaintext1 = arguments.get("plaintext");
                                // end new
                                String resultString1 = "";
                                char[] passwordChar1 = password1.toCharArray();
                                resultString1 = aesGcmPbkdf2EncryptToBase64Android(passwordChar1, iterations1, plaintext1);
                                result.success(resultString1);
                                break;
                            case "getCryptDecString":
                                String password2= arguments.get("password");
                                String ciphertext2 = arguments.get("ciphertext");
                                // end new
                                String resultString2 = "";
                                char[] passwordChar2 = password2.toCharArray();
                                resultString2 = aesGcmPbkdf2DecryptFromBase64Android(passwordChar2, ciphertext2);
                                result.success(resultString2);
                                break;
                            case "getCryptEncStringOld":
                                String password1o = arguments.get("password");
                                String plaintext1o = arguments.get("plaintext");
                                // end new
                                String resultString1o = "";
                                char[] passwordChar1o = password1o.toCharArray();
                                resultString1o = aesGcmPbkdf2EncryptToBase64AndroidOld(passwordChar1o, plaintext1o);
                                result.success(resultString1o);
                                break;
                            case "getCryptDecStringOld":
                                String password2old= arguments.get("password");
                                String ciphertext2old = arguments.get("ciphertext");
                                // end new
                                String resultString2old = "";
                                char[] passwordChar2old = password2old.toCharArray();
                                resultString2old = aesGcmPbkdf2DecryptFromBase64AndroidOld(passwordChar2old, ciphertext2old);
                                result.success(resultString2old);
                                break;
                            case "getReturnString":
                                String name = arguments.get("name");
                                String gender = arguments.get("gender");
                                // end new
                                String resultString = "";
                                resultString = "newString: " + name + " is " + gender;
                                //int batteryLevel = getBatteryLevel();
                                result.success(resultString);
                                break;
                            default:
                                result.notImplemented();
                                break;
                        }

                    }
                }
        );

        new MethodChannel(flutterEngine.getDartExecutor(), BATTERY_CHANNEL).setMethodCallHandler(
                new MethodCallHandler() {
                    @Override
                    public void onMethodCall(MethodCall call, Result result) {
                        if (call.method.equals("getBatteryLevel")) {
                            // new
                            Map<String, String> arguments = call.arguments();
                            String name = arguments.get("name");
                            // end new

                            int batteryLevel = getBatteryLevel();

                            if (batteryLevel != -1) {
                                //result.success(batteryLevel);
                                result.success(name + " says on Android: " + batteryLevel);
                            } else {
                                result.error("UNAVAILABLE", "Battery level not available.", null);
                            }
                        } else {
                            result.notImplemented();
                        }
                    }
                }
        );
    }

    /*
    private BroadcastReceiver createChargingStateChangeReceiver(final EventSink events) {
        return new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                int status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
                if (status == BatteryManager.BATTERY_STATUS_UNKNOWN) {
                    events.error("UNAVAILABLE", "Charging status unavailable", null);
                } else {
                    boolean isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                            status == BatteryManager.BATTERY_STATUS_FULL;
                    events.success(isCharging ? "charging" : "discharging");
                }
            }
        };
    }
     */

    private int getBatteryLevel() {
        if (VERSION.SDK_INT >= VERSION_CODES.LOLLIPOP) {
            BatteryManager batteryManager = (BatteryManager) getSystemService(BATTERY_SERVICE);
            return batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY);
        } else {
            Intent intent = new ContextWrapper(getApplicationContext()).
                    registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            return (intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) * 100) /
                    intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        }
    }

    private static byte[] generateSalt32Byte() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private static byte[] generateRandomNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[12];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    public static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        return ByteBuffer
                .allocate(a.length + b.length)
                .put(a).put(b)
                .array();
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2EncryptToBase64Android(char[] passphrase, String iterationsString, String data) {
        int PBKDF2_ITERATIONS = 0;
        try {
            PBKDF2_ITERATIONS = Integer.parseInt(iterationsString);
        } catch(NumberFormatException nfe) {
            PBKDF2_ITERATIONS = 10000; // minimum
        }
        //int PBKDF2_ITERATIONS = 10001;
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        byte[] salt = generateSalt32Byte();
        byte[] nonce = generateRandomNonce();
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NOPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] ciphertextWithTag = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String saltBase64 = base64Encoding(salt);
            String roundsString = String.valueOf(PBKDF2_ITERATIONS);
            String nonceBase64 = base64Encoding(nonce);
            String ciphertextBase64 = base64Encoding(ciphertextWithTag);
            return
               saltBase64 + ":" + roundsString + ":" + nonceBase64 + ":" + ciphertextBase64;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2DecryptFromBase64Android(char[] passphrase, String data) {
        String[] parts = data.split(":", 0);
        byte[] salt = base64Decoding(parts[0]);
        String iterationsString = parts[1];
        byte[] nonce = base64Decoding(parts[2]);
        byte[] ciphertextWithTag = base64Decoding(parts[3]);
        int PBKDF2_ITERATIONS = 0;
        try {
            PBKDF2_ITERATIONS = Integer.parseInt(iterationsString);
        } catch(NumberFormatException nfe) {
            PBKDF2_ITERATIONS = 10000; // minimum
        }
        if ((salt.length != 32) | (nonce.length != 12) | (ciphertextWithTag.length < 16)) return "";
        // key derivation
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NOPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] decryptedtext = cipher.doFinal(ciphertextWithTag);
            return new String(decryptedtext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2EncryptToBase64AndroidOld(char[] passphrase, String data) {
        int PBKDF2_ITERATIONS = 10001;
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        byte[] salt = generateSalt32Byte();
        byte[] nonce = generateRandomNonce();
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NOPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] ciphertextWithTag = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            //byte[] ciphertext = new byte[(ciphertextWithTag.length-16)];
            //byte[] gcmTag = new byte[16];
            //System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, (ciphertextWithTag.length - 16));
            //System.arraycopy(ciphertextWithTag, (ciphertextWithTag.length-16), gcmTag, 0, 16);
            String saltBase64 = base64Encoding(salt);
            String nonceBase64 = base64Encoding(nonce);
            //String ciphertextBase64 = base64Encoding(ciphertext);
            String ciphertextBase64 = base64Encoding(ciphertextWithTag);
            //String gcmTagBase64 = base64Encoding(gcmTag);
            return
                    //+ saltBase64 + ":" + nonceBase64 + ":" + ciphertextBase64 + ":" + gcmTagBase64
                    saltBase64 + ":" + nonceBase64 + ":" + ciphertextBase64;
            //+ "\n" + masterkeyImportFooterLine;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2DecryptFromBase64AndroidOld(char[] passphrase, String data) {
        int PBKDF2_ITERATIONS = 10001;
        String[] parts = data.split(":", 0);
        byte[] salt = base64Decoding(parts[0]);
        byte[] nonce = base64Decoding(parts[1]);
        byte[] ciphertextWithTag = base64Decoding(parts[2]);
        //byte[] ciphertextWithoutTag = base64Decoding(parts[2]);
        //byte[] gcmTag = base64Decoding(parts[3]);
        if ((salt.length != 32) | (nonce.length != 12) | (ciphertextWithTag.length < 16)) return "";
        // key derivation
        SecretKeyFactory secretKeyFactory = null;
        byte[] key;
        try {
            secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keySpec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, 32 * 8);
            key = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return "";
        }
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NOPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
            byte[] decryptedtext = cipher.doFinal(ciphertextWithTag);
            return new String(decryptedtext);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return "";
        }
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2EncryptToBase64(char[] password, String data) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        int PBKDF2_ITERATIONS = 15000;
        byte[] salt = generateSalt32Byte();
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 32 * 8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
        byte[] nonce = generateRandomNonce();
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
        byte[] ciphertextWithTag = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = new byte[(ciphertextWithTag.length-16)];
        byte[] gcmTag = new byte[16];
        System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, (ciphertextWithTag.length - 16));
        System.arraycopy(ciphertextWithTag, (ciphertextWithTag.length-16), gcmTag, 0, 16);
        String saltBase64 = base64Encoding(salt);
        String nonceBase64 = base64Encoding(nonce);
        String ciphertextBase64 = base64Encoding(ciphertext);
        String gcmTagBase64 = base64Encoding(gcmTag);
        return saltBase64 + ":" + nonceBase64 + ":" + ciphertextBase64 + ":" + gcmTagBase64;
    }

    @RequiresApi(api = VERSION_CODES.KITKAT)
    private static String aesGcmPbkdf2DecryptFromBase64(char[] password, String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        String[] parts = data.split(":", 0);
        byte[] salt = base64Decoding(parts[0]);
        byte[] nonce = base64Decoding(parts[1]);
        byte[] ciphertextWithoutTag = base64Decoding(parts[2]);
        byte[] gcmTag = base64Decoding(parts[3]);
        byte[] encryptedData = concatenateByteArrays(ciphertextWithoutTag, gcmTag);
        int PBKDF2_ITERATIONS = 15000;
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, 32 * 8);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyFactory.generateSecret(keySpec).getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmParameterSpec);
        return new String(cipher.doFinal(encryptedData));
    }

    private static String base64Encoding(byte[] input) {
        return Base64.encodeToString(input, Base64.NO_WRAP);
    }

    private static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }
}
