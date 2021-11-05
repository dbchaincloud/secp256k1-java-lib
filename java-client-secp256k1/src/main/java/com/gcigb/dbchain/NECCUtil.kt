package com.gcigb.dbchain

import org.spongycastle.jce.provider.BouncyCastleProvider
import java.security.Security

object NECCUtil {

    init {
        System.loadLibrary("ecc")
        // Android里的 secp256k1 被阉割了，需要添加这行代码
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    external fun encrypt(message: String, publicKeyBase64: String): String
    external fun decrypt(message: String, privateKeyBase64: String): String
}