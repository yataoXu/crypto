package com.crypto.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.util.Base64;

public class DesUtil {

    public static String encryptDES(String encryptString, String key) {
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(1, new SecretKeySpec(key.getBytes(), "DES"));
            byte[] encryptedData = cipher.doFinal(encryptString.getBytes("UTF-8"));
            String strBase64 = Base64.getEncoder().encodeToString(encryptedData);
            String strURL = URLEncoder.encode(strBase64, "UTF-8");
            return strURL;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encryptStr(String siteCode, String accountNo, String amt, String date, String taxpayerNo, String key) {
        StringBuilder sb = new StringBuilder();
        return encryptStr(sb.append(siteCode).append(accountNo).append(amt).append(date).append(taxpayerNo).toString(), key);
    }

    public static String encryptStr(String data, String key) {
        return encryptDES(data, key);
    }


}