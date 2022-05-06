package com.freestyle.cipher;

import java.util.Arrays;

/**
 * Created by rocklee on 2022/5/5 16:17
 */
public abstract class AbstractCipherUtil implements CipherUtil{
  @Override
  public byte[] encryptWithSalt(byte[] content, byte[]... salt) {
    byte[] bSalt=salt.length>0?salt[0]: CipherUtil.getRandomSalt(5);
    if (bSalt.length>20){
      throw new IllegalArgumentException("Salt is too long !");
    }
    // 合并两个数组
    byte[] dest = new byte[content.length + bSalt.length+SPLIT.length];
    System.arraycopy(bSalt, 0, dest, 0, bSalt.length);
    System.arraycopy(SPLIT, 0, dest, bSalt.length, SPLIT.length);
    System.arraycopy(content, 0, dest, bSalt.length+SPLIT.length, content.length);
    return encrypt(dest);
  }
  @Override
  public byte[] decryptWithSalt(byte[] secret) {
    byte[] rawBytes=decrypt(secret);
    byte[] split;
    for (int i=0;i<rawBytes.length-2;i++){
      split= Arrays.copyOfRange(rawBytes,i,i+3);
      if (Arrays.equals(split,SPLIT)){
        byte[] result=Arrays.copyOfRange(rawBytes,i+3,rawBytes.length-1);
        return result;
      }
    }
    return null;
  }
}
