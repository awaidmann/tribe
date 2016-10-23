package com.warnable.plugin;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Random;

import javax.security.auth.x500.X500Principal;

public class KeyManager {
    public static final int KEY_PAIR_GENERATED = 1;
    public static final int KEY_PAIR_VALID = 0;
    public static final int KEY_PAIR_FAILED = -1;

    private static final int RANDOM_BIT_SIZE = 12;
    private static final int PEM_LINE_LENGTH = 64;
    private static final int EC_KEY_SIZE = 256;

    private static final String KEY_STORE = "AndroidKeyStore";
    private static final String PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_FOOTER = "-----END PUBLIC KEY-----";

    public static int generateKeyPairIfNecessary(Context context, String uid) throws Exception {
      Certificate cert = getCertificate(uid);
      boolean genStatus = false;

      if (cert != null && cert instanceof X509Certificate) {
        X509Certificate x509 = (X509Certificate)cert;
        try {
          x509.checkValidity();
          return KEY_PAIR_VALID;
        } catch (Exception e) {
          return generateKeyPair(context, uid) ? KEY_PAIR_GENERATED : KEY_PAIR_FAILED;
        }
      } else {
        return generateKeyPair(context, uid) ? KEY_PAIR_GENERATED : KEY_PAIR_FAILED;
      }
    }

    public static boolean generateKeyPair(Context context, String uid) throws Exception {
        X500Principal subject = new X500Principal("CN=" + uid);
        Calendar start = GregorianCalendar.getInstance();
        Calendar end = new GregorianCalendar();
        end.setLenient(true);
        end.set(start.get(Calendar.YEAR) + 1, start.get(Calendar.MONTH), start.get(Calendar.DAY_OF_MONTH));
        BigInteger serialNum = new BigInteger(RANDOM_BIT_SIZE, new Random());

        KeyguardManager kgm = (KeyguardManager)context.getSystemService(context.KEYGUARD_SERVICE);
        KeyPair pair;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    KEY_STORE
            );

            kpg.initialize(new KeyGenParameterSpec.Builder( uid,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setKeySize(EC_KEY_SIZE)
                    .setCertificateSerialNumber(serialNum)
                    .setCertificateSubject(subject)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .build());
            pair = kpg.generateKeyPair();

        } else {
            KeyPairGeneratorSpec.Builder kpgb = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(uid)
                    .setSubject(subject)
                    .setKeyType(KeyProperties.KEY_ALGORITHM_EC)
                    .setKeySize(EC_KEY_SIZE)
                    .setSerialNumber(serialNum)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime());

            KeyPairGeneratorSpec kpgs = kgm.isKeyguardSecure() ? kpgb.setEncryptionRequired().build() : kpgb.build();
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEY_STORE);
            kpg.initialize(kpgs);
            pair = kpg.generateKeyPair();
        }

        return (pair != null);
    }

    public static PublicKey publicKeyFromString(String pkStr, String keyID) throws Exception {
        String formattedPK = pkStr.replaceAll("\n", "");
        formattedPK = formattedPK.replaceAll(PEM_HEADER, "");
        formattedPK = formattedPK.replaceAll(PEM_FOOTER, "");

        byte[] byteKey = Base64.decode(formattedPK.getBytes(), Base64.DEFAULT);
        X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(byteKey);

        KeyFactory kf = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC);
        PublicKey pk = kf.generatePublic(x509publicKey);

        // TODO: Permanently store new key in some keystore
        return pk;
    }

    public static String getPEMPublicKey(String uid) throws Exception {
      PublicKey rawPK = getPublicKey(uid);
      if (rawPK != null) {
        String pkStr = Base64.encodeToString(rawPK.getEncoded(), Base64.NO_WRAP);
        String keyPEM = PEM_HEADER + "\n";

        int lineIndex = 0;
        while(pkStr.length() - lineIndex > PEM_LINE_LENGTH) {
          lineIndex += PEM_LINE_LENGTH;
          keyPEM += pkStr.substring(lineIndex - PEM_LINE_LENGTH, lineIndex) + "\n";
        }
        keyPEM += pkStr.substring(lineIndex) + "\n" + PEM_FOOTER;
        return keyPEM;
      } else {
        return null;
      }
    }

    public static PublicKey getPublicKey(String uid) throws Exception {
      Certificate cert = getCertificate(uid);
      if (cert != null) {
        return cert.getPublicKey();
      }
      return null;
    }

    public static PrivateKey getPrivateKey(String uid) throws Exception {
        KeyStore ks = getKeyStore();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return (PrivateKey) ks.getKey(uid, null);
        } else {
          KeyStore.PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry)ks.getEntry(uid, null);
          if (pke != null) {
            return pke.getPrivateKey();
          }
        }
        return null;
    }

    public static Certificate getCertificate(String uid) throws Exception {
      KeyStore ks = getKeyStore();
      KeyStore.PrivateKeyEntry pke = (KeyStore.PrivateKeyEntry)ks.getEntry(uid, null);
      if (pke != null) {
        return pke.getCertificate();
      }
      return null;
    }

    private static KeyStore getKeyStore() throws Exception {
      KeyStore ks = KeyStore.getInstance(KEY_STORE);
      ks.load(null);
      return ks;
    }
}
