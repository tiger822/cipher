package com.freestyle.cipher;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.sampled.Clip;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * 非线程安全
 * AES数据加密，适应进行大数据加解密，要注意保存好密钥
 * 此类采用AES128-CBC模式进行加解密，故需要设置初始向量
 * Created by rocklee on 2022/2/11 11:53
 */
public class AESUtil extends AbstractCipherUtil{
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
    byte paddingLen=(byte)(blockSize-content.length%blockSize);
    int byteLen=content.length%blockSize==0?content.length:content.length+paddingLen;
    byte[] contentToEncrypt=new byte[byteLen];
    System.arraycopy(content,0,contentToEncrypt,0,content.length);
    try {
      cipher.init(Cipher.ENCRYPT_MODE,keySpec,ivParameterSpec);
      byte[] encryptedBytes=cipher.doFinal(contentToEncrypt);
      byte[] retVal=new byte[encryptedBytes.length+1];
      retVal[0]=paddingLen;
      System.arraycopy(encryptedBytes,0,retVal,1,encryptedBytes.length);
      return retVal;
      //return encryptedBytes;
    } catch (InvalidKeyException | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException e) {
      e.printStackTrace();
    }
    return null;
  }




  @Override
  public byte[] decrypt(byte[] secret) {
    if (secret==null||secret.length<2)return null;
    try {
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
     /* byte [] contentToDecrypt= cipher.doFinal(secret);
      return contentToDecrypt;*/

      byte paddingLen=secret[0];
      byte[] contentToDecrypt=new byte[secret.length-1];
      System.arraycopy(secret,1,contentToDecrypt,0,secret.length-1);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec);
      contentToDecrypt= cipher.doFinal(contentToDecrypt);
      byte[] retVal=new byte[contentToDecrypt.length-paddingLen];
      System.arraycopy(contentToDecrypt,0,retVal,0,contentToDecrypt.length-paddingLen);
      return retVal;


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
