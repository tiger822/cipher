package com.freestyle.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 非线程安全
 * 加密：公钥加密，私钥解密
 * 签名：私钥签名，公钥验证
 * 最好不要用RSA加密大数据，速度慢(RSA一次加密数据不能大于245bytes)。推荐AES加密大数据，RSA加密AES密钥
 * Created by rocklee on 2022/2/11 10:01
 */
public class RSAUtil implements CipherUtil {
  private static final Logger logger = LoggerFactory.getLogger(RSAUtil.class);
  private RSAPublicKey publicKey;
  private RSAPrivateKey privateKey;
  private Cipher cipher;


  public RSAUtil(String publicKey, String privateKey) {
    this(Base64Utils.decode(publicKey), Base64Utils.decode(privateKey));
  }
  public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
    return CipherUtil.buildKeyPair("RSA");
  }
  public RSAUtil(byte[] publicKey, byte[] privateKey) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      if (publicKey != null && publicKey.length > 0) {
        this.publicKey = (RSAPublicKey)keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
      }
      if (privateKey != null && privateKey.length > 0) {
        this.privateKey = (RSAPrivateKey)keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public RSAUtil(String publicKey) {
    this(Base64Utils.decode(publicKey));
  }

  public RSAUtil(byte[] publicKey) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      if (publicKey != null && publicKey.length > 0) {
        this.publicKey = (RSAPublicKey)keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
  public RSAUtil(RSAPublicKey publicKey){
    this.publicKey=publicKey;
  }
  public RSAUtil(RSAPrivateKey privateKey){
    this.privateKey=privateKey;
  }
  public RSAUtil(RSAPublicKey publicKey, RSAPrivateCrtKey privateKey){
    this.publicKey=publicKey;
    this.privateKey=privateKey;
  }

  @Override
  public byte[] encrypt(byte[] content) {
    if (publicKey == null) {
      throw new RuntimeException("public key is null.");
    }

    if (content == null) {
      return null;
    }

    try {
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      int size;
      int left;

      size = publicKey.getModulus().bitLength() / 8 - 11;
      ByteArrayOutputStream baos = new ByteArrayOutputStream((content.length + size - 1) / size * (size + 11));
      for (int i = 0; i < content.length; ) {
        left = content.length - i;
        if (left > size) {
          cipher.update(content, i, size);
          i += size;
        } else {
          cipher.update(content, i, left);
          i += left;
        }
        baos.write(cipher.doFinal());
      }
      return baos.toByteArray();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public byte[] decrypt(byte[] secret) {
    if (privateKey == null) {
      throw new RuntimeException("private key is null.");
    }

    if (secret == null) {
      return null;
    }

    try {
      cipher.init(Cipher.DECRYPT_MODE, privateKey);

      int size = privateKey.getModulus().bitLength() / 8;
      ByteArrayOutputStream baos = new ByteArrayOutputStream((secret.length + size - 12) / (size - 11) * size);
      int left ;
      for (int i = 0; i < secret.length; ) {
        left = secret.length - i;
        if (left > size) {
          cipher.update(secret, i, size);
          i += size;
        } else {
          cipher.update(secret, i, left);
          i += left;
        }
        baos.write(cipher.doFinal());
      }
      return baos.toByteArray();
    } catch (Exception e) {
      logger.error("rsa decrypt failed.", e);
    }
    return null;
  }

  @Override
  public void initCipher() {
    try {
      cipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      e.printStackTrace();
    }
  }

  @Override
  public byte[] sign(byte[] content) {
    if (privateKey == null) {
      throw new RuntimeException("private key is null.");
    }
    if (content == null) {
      return null;
    }
    try {
      Signature signature = Signature.getInstance("SHA1WithRSA");
      signature.initSign(privateKey);
      signature.update(content);
      return signature.sign();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verify(byte[] sign, byte[] content) {
    if (publicKey == null) {
      throw new RuntimeException("public key is null.");
    }
    if (sign == null || content == null) {
      return false;
    }
    try {
      Signature signature = Signature.getInstance("SHA1WithRSA");
      signature.initVerify(publicKey);
      signature.update(content);
      return signature.verify(sign);
    } catch (Exception e) {
      logger.error("rsa verify failed.", e);
    }
    return false;
  }
}
