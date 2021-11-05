package dbchain.client.java.secp256k1

import com.gcigb.dbchain.NECCUtil.decrypt
import com.gcigb.dbchain.NECCUtil.encrypt
import dbchain.client.java.secp256k1.address.AddressUtil
import dbchain.java.client.base.IDBChainEncrypt
import org.bitcoinj.crypto.DeterministicKey
import org.spongycastle.util.encoders.Base64
import org.spongycastle.util.encoders.Hex
import org.web3j.crypto.ECKeyPair
import org.web3j.utils.Numeric
import java.util.*

class Secp256k1Encrypt : IDBChainEncrypt {

    override val pubKeyType: String
        get() = "tendermint/PubKeySecp256k1"

    /**
     * 签名
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param data ByteArray
     * @return ByteArray
     */
    override fun sign(privateByteArray: ByteArray, data: ByteArray): ByteArray {
        return ECCUtil.signECDSA(privateByteArray, data)
    }

    /**
     * 验证签名
     * @param publicKeyByteArray ByteArray 公钥 64 个字节
     * @param data ByteArray 明文
     * @param sign ByteArray 签名
     * @return Boolean true 通过，否则失败
     */
    override fun verify(publicKeyByteArray: ByteArray, data: ByteArray, sign: ByteArray): Boolean {
        return ECCUtil.verifySig(publicKeyByteArray, data, sign)
    }

    /**
     * 加密
     * @param publicKeyByteArray ByteArray 公钥 33 个字节
     * @param data ByteArray 明文
     * @return ByteArray 密文
     */
    override fun encrypt(publicKeyByteArray: ByteArray, data: ByteArray): ByteArray {
        val publicKeyBase64 = Base64.toBase64String(publicKeyByteArray)
        val encrypt = encrypt(String(data), publicKeyBase64)
        return encrypt.toByteArray()
    }

    /**
     * 解密
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param data ByteArray 密文
     * @return ByteArray 解密后的明文
     */
    override fun decrypt(privateByteArray: ByteArray, data: ByteArray): ByteArray {
        val privateKeyBase64 = Base64.toBase64String(privateByteArray)
        val decrypt = decrypt(String(data), privateKeyBase64)
        return decrypt.toByteArray()
    }

    /**
     * 公钥生成地址
     * @param publicKeyByteArray33 ByteArray 33 个字节的公钥（压缩过的）
     * @return String 地址
     */
    override fun generateAddressByPublicKeyByteArray33(publicKeyByteArray33: ByteArray): String {
        return AddressUtil.generateAddress(Hex.toHexString(publicKeyByteArray33))
    }

    /**
     * 根据私钥生成公钥
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param dkKey DeterministicKey
     * @return ByteArray
     */
    override fun generatePublicKey33ByPrivateKey(
        privateByteArray: ByteArray,
        dkKey: DeterministicKey?
    ): ByteArray {
        return dkKey?.pubKey ?: byteArrayOf()
    }

    /**
     * 根据私钥生成公钥
     * @param privateByteArray ByteArray 私钥 32 个字节
     * @param dkKey DeterministicKey
     * @return ByteArray
     */
    override fun generatePublicKey64ByPrivateKey(
        privateByteArray: ByteArray,
        dkKey: DeterministicKey?
    ): ByteArray {
        dkKey ?: return byteArrayOf()
        //获取密钥对
        val keyPair: ECKeyPair = ECKeyPair.create(dkKey.privKeyBytes)
        var publicKeyDer: String = Numeric.toHexStringNoPrefix(keyPair.publicKey)
        while (publicKeyDer.length < 128) {
            //长度小于128前面需要补0
            publicKeyDer = "0$publicKeyDer"
        }
        return Hex.decode(publicKeyDer)
    }
}