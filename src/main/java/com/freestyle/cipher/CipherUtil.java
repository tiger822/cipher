package com.freestyle.cipher;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by rocklee on 2022/2/11 10:31
 */
public interface CipherUtil {
  static RSAPublicKey loadPublicKey(byte[] publicKey) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
      return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  static RSAPrivateKey loadPrivateKey(byte[] privateKey) {
    try {
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  static KeyPair buildKeyPair(String algorithm) throws NoSuchAlgorithmException {
    final int keySize = 2048;
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
    keyPairGenerator.initialize(keySize);
    return keyPairGenerator.genKeyPair();
  }

  byte[] encrypt(byte[] content);

  byte[] decrypt(byte[] secret);
  void initCipher();

  byte[] sign(byte[] content);

  boolean verify(byte[] sign, byte[] content);
}
