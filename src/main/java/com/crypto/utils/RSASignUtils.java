package com.crypto.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @author yatao.xu
 * @version 1.0.0
 * @date 2021-01-07
 **/
public class RSASignUtils {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * @param base64Str      需要被签名的内容
     * @param privateKeyPath 私钥地址
     * @param keyType        密钥文件格式
     * @return 签名后的内容
     * @throws Exception
     */
    public static String RSAMD5Sign(String base64Str, String privateKeyPath, String keyType) {

        byte[] data;
        try {
            data = (new BASE64Decoder()).decodeBuffer(base64Str);
        } catch (IOException e) {
            return "base64Str 转 byte[] 异常";
        }
        if ("1".equals(keyType)) {
            return pkcs8EncryptByPrivateKey(data, privateKeyPath);
        } else {
            return "不支持的加密方式";
        }
    }

    /**
     * 用私钥对信息进行签名
     *
     * @param content    名文
     * @param privateKey 私钥地址
     * @return
     */
    public static String pkcs8EncryptByPrivateKey(byte[] content, String privateKey) {
        if (content == null) {
            return "需要被加密的内容为空";
        }
        if (privateKey == null || privateKey.length() == 0) {
            return "私钥地址为空";
        }
        try {
            // 解密由base64编码的私钥
            byte[] keyBytes = Files.readAllBytes(Paths.get(privateKey));
            String pem = new String(keyBytes);
            pem = pem.replace("-----BEGIN PRIVATE KEY-----", "");
            pem = pem.replace("-----END PRIVATE KEY-----", "");
            pem = pem.replace("\n", "");
            byte[] decoded = (new BASE64Decoder()).decodeBuffer(pem);

            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(priKey);
            signature.update(content);
            byte[] sign = signature.sign();
            String s = new BASE64Encoder().encodeBuffer(sign);
            System.out.println(s);
            return s;
        } catch (Exception e) {
            return "用私钥对信息进行签名失败";
        }
    }


    public static void main(String[] args) {
        String rz = RSAMD5Sign(new BASE64Encoder().encodeBuffer("中国".getBytes()), "/Users/xuyatao/Downloads/jih_8.pem", "1");
        String rs = "CkWmUmTkDDK+zRD+GHcwPAgQtPjK0bf6Vj5tJ8Uy/k/hEB2O/nBM9Qgw2nLaFR11fzsVpmbkHJArBIpnbB/5P5SrXWVqQCaDL0NV9jSlbQqZMXgSFJCC6SzlcNrYMP+d2afbNk7jlv5aArKcLKTzkNHdLkN9YduPE9ejs5Qd788=";

        if ((rz.replaceAll("\n", "")).equals(rs)) {
            System.out.println(true);
        } else {
            System.out.println(false);
        }
    }
}
