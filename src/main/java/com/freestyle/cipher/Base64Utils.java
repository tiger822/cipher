package com.freestyle.cipher;

import java.util.Base64;

/**
 * Created by rocklee on 2022/2/11 10:21
 */
public class Base64Utils {
  public static byte[] decode(String content){
    return Base64.getDecoder().decode(content);
  }
  public static  String encode(byte[] content){
    return Base64.getEncoder().encodeToString(content);
  }
}
