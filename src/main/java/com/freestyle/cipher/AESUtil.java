package com.freestyle.cipher;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * 非线程安全
 * AES数据加密，适应进行大数据加解密，要注意保存好密钥
 * 此类采用AES128-CBC模式进行加解密，故需要设置初始向量
 * Created by rocklee on 2022/2/11 11:53
 */
public class AESUtil implements CipherUtil{
  private final String key;
  private final String iv;
  private Cipher cipher;
  private SecretKeySpec keySpec;
  private IvParameterSpec ivParameterSpec;

  public AESUtil(String key, String iv) {
    //必须保证key和初始向量都是16位长
    if (key.length()!=16){
        key= StringUtils.left(StringUtils.rightPad(key,16),16);
    }
    if (iv.length()!=16){
      iv= StringUtils.left(StringUtils.rightPad(iv,16),16);
    }
    this.key = key;
    this.iv = iv;
  }

  @Override
  public byte[] encrypt(byte[] content) {
    int blockSize=cipher.getBlockSize();
    int byteLeng=content.length%blockSize==0?content.length:content.length+(blockSize-content.length%blockSize);
    byte[] contentToEncrypt=new byte[byteLeng];
    System.arraycopy(content,0,contentToEncrypt,0,content.length);
    try {
      cipher.init(Cipher.ENCRYPT_MODE,keySpec,ivParameterSpec);
      return cipher.doFinal(contentToEncrypt);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  public byte[] decrypt(byte[] secret) {
    try {
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
      return cipher.doFinal(secret);
    } catch (BadPaddingException|IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  public void initCipher() {
    try {
      cipher = Cipher.getInstance("AES/CBC/NoPadding");
      keySpec=new SecretKeySpec(key.getBytes(),"AES");
      ivParameterSpec=new IvParameterSpec(iv.getBytes());
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      e.printStackTrace();
    }
  }

  @Override
  public byte[] sign(byte[] content) {
    throw new IllegalAccessError("No support");
  }

  @Override
  public boolean verify(byte[] sign, byte[] content) {
    throw new IllegalAccessError("No support");
  }
}
