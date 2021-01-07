package com.crypto.enums;

/**
 * RSA 密钥文件格式
 *
 * @author yatao.xu
 * @version 1.0.0
 * @date 2021-01-05
 **/
public enum RSAKeyFileFormat {

    UNKNOWN("unknown", "未知"),
    PKCS1("PKCS#1", "PKCS#7"),
    PKCS8("PKCS#8", "PKCS#8"),
    ;
    private String name;
    private String desc;

    RSAKeyFileFormat(String name, String desc) {
        this.name = name;
        this.desc = desc;
    }

    public String getName() {
        return name;
    }

    public String getDesc() {
        return desc;
    }


    public static RSAKeyFileFormat findByName(String name) {
        if (name == null || name.length() == 0) {
            return UNKNOWN;
        }
        for (RSAKeyFileFormat item : RSAKeyFileFormat.values()) {
            if (item.getName().equals(name)) {
                return item;
            }
        }
        return UNKNOWN;
    }
}

