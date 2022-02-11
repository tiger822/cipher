import com.freestyle.cipher.AESUtil;
import com.freestyle.cipher.Base64Utils;
import com.freestyle.cipher.CipherUtil;
import com.freestyle.cipher.RSAUtil;
import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;
import org.junit.Test;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

/**
 * Created by rocklee on 2022/2/11 10:29
 */
public class TestRsa {
  public byte[] genBigData(String source,int size){
    StringBuilder sb=new StringBuilder();
    for (int i=0;i<1000;i++){
      sb.append(source).append("\n");
    }
    byte[] b=sb.toString().getBytes();
    try(ByteOutputStream bos=new ByteOutputStream(size)){
      do {
        bos.write(b);
      } while (bos.size() < size);
      return bos.getBytes();
    }
  }
  @Test
  public void testCipher() throws NoSuchAlgorithmException {
    KeyPair keyPair= RSAUtil.buildKeyPair();
    String publicKeyStr= Base64Utils.encode( keyPair.getPublic().getEncoded());
    String privateKeyStr= Base64Utils.encode(keyPair.getPrivate().getEncoded());
    System.out.println("public key:"+publicKeyStr);
    System.out.println("private key:"+privateKeyStr);
    CipherUtil cipher1=new RSAUtil(publicKeyStr);
    cipher1.initCipher();
    String rawText="我是要加密的字符串，This is a string that needs to be encrypted";
    byte[] encrypted= cipher1.encrypt(rawText.getBytes());
    System.out.println("加密后的内容："+Base64Utils.encode(encrypted));
    byte[] e2=cipher1.encrypt("String 2".getBytes());

    CipherUtil cipher2=new RSAUtil((RSAPrivateCrtKey) keyPair.getPrivate());
    cipher2.initCipher();
    String plaintext=new String(cipher2.decrypt(encrypted));
    System.out.println("解密后的明文:"+plaintext);
    System.out.println(new String(cipher2.decrypt(e2)));

    byte[] b=genBigData(plaintext,1024*1024*10);
    b= cipher1.encrypt(b);
    b=cipher2.decrypt(b);
    String s=new String(b);
    System.out.println(s.substring(s.length()-100));
  }
  @Test
  public void testSign() throws NoSuchAlgorithmException {
    String test="this the test that need to protect";

    KeyPair keyPair= RSAUtil.buildKeyPair();
    CipherUtil cipherUtil=new RSAUtil((RSAPrivateKey) keyPair.getPrivate());

    byte[] signCode=cipherUtil.sign(test.getBytes());
    System.out.println("签名："+Base64Utils.encode(signCode));

    CipherUtil cipherUtil2=new RSAUtil(keyPair.getPublic().getEncoded());
    if (cipherUtil2.verify(signCode,test.getBytes())){
      System.out.println("验证通过");
    }
    if (!cipherUtil2.verify(signCode,(test+".").getBytes())){
      System.out.println("验证失败");
    }
  }
  @Test
  public void testAES(){
    String rawText="这是加密字符串， I need to encrypt.";
    String password="abcd@1234";
    String iv="123456";
    CipherUtil aes=new AESUtil(password,iv);
    aes.initCipher();
    byte[] secret=null;
    for (int i=0;i<3;i++){
      secret= aes.encrypt(rawText.getBytes());
      System.out.println("AES加密后:"+Base64Utils.encode(secret));
    }

    CipherUtil aesDesc=new AESUtil(password,iv);
    aesDesc.initCipher();
    byte[] plaintContent=aesDesc.decrypt(secret);
    System.out.println("解密后："+new String(plaintContent));


    byte[] b=genBigData(rawText,1024*1024*10);
    byte[] e=aes.encrypt(b);
    byte[] p=aesDesc.decrypt(e);
    if (Arrays.equals(b,p)){
      System.out.println("加解密完成");
    }
  }
}
