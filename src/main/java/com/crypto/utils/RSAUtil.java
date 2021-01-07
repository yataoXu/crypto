package com.crypto.utils;

import com.crypto.enums.RSAKeyFileFormat;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author yatao.xu
 * @version 1.0.0
 * @date 2021-01-07
 **/


public class RSAUtil {

    public static final String KEY_ALGORITHM = "RSA";

    /**
     * @param content         需要被签名的内容
     * @param privateKeyBytes 私钥
     * @param keyType         密钥文件格式
     * @return 签名后的内容
     * @throws Exception
     */
    public static String RSAMD5Sign(String content, byte[] privateKeyBytes, String keyType) throws Exception {

        RSAKeyFileFormat KeyFileFormat = RSAKeyFileFormat.findByName(keyType);
        switch (KeyFileFormat) {
            case PKCS8:
                PrivateKey privateKey = getRSAPrivateKey(privateKeyBytes);
                byte[] bytes = encryptByPrivateKey(content.getBytes(), privateKey);
                return encryptBASE64(bytes);
            default:

                throw new RuntimeException("暂不支持该密钥签名");
        }

    }

    public static PrivateKey getRSAPrivateKey(byte[] keyBytes) throws IOException {

//        byte[] keyBytes = Files.readAllBytes(Paths.get(pkcs8_rsa_private_key));
        String pem = new String(keyBytes);
        pem = pem.replace("-----BEGIN PRIVATE KEY-----", "");
        pem = pem.replace("-----END PRIVATE KEY-----", "");
        pem = pem.replace("\n", "");

        byte[] decoded = (new BASE64Decoder()).decodeBuffer(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        PrivateKey privateKey = null;

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(spec);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }


    /**
     * 用私钥加密
     *
     * @param data       明文
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, PrivateKey privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

}
