# cipher
a java project for easy to cipher

# Sample
## to encrypt/decrypt string
```
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
```