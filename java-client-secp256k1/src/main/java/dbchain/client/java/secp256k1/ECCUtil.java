package dbchain.client.java.secp256k1;

import com.gcigb.dbchain.NECCUtil;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECCurve;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.Base64;

/**
 * ECC安全编码组件
 *
 * @author Jocerly
 */
public class ECCUtil {
    private static final String curve = "secp256k1";
    private static final String SIGNALGORITHMS = "SHA256withECDSA";
    private static final String ALGORITHM = "ECDSA";
    private static final String TAG = "ECCUtil";

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public static byte[] signECDSA(byte[] privateKeyBytes, byte[] data) {
        byte[] decode;
        do {
            byte[] signResult = sign(privateKeyBytes, data);
            decode = decodeDer(signResult);
        } while (decode.length != 64);
        return decode;
    }

    private static byte[] sign(byte[] privateKeyBytes, byte[] data) {
        try {
            // 执行签名
            Signature signature = Signature.getInstance(SIGNALGORITHMS);
            signature.initSign(loadPrivateKey(privateKeyBytes));
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String encryptData(byte[] publicKeyBytes, String message) {
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKeyBytes);
        return NECCUtil.INSTANCE.encrypt(message, publicKeyBase64);
    }

    public static String decryptData(byte[] privateKeyBytes, String message) {
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyBytes);
        return NECCUtil.INSTANCE.decrypt(message, privateKeyBase64);
    }

    public static boolean verifySig(byte[] publicKeyBytes, byte[] data, byte[] sig) {
        try {
            Signature signer = Signature.getInstance(SIGNALGORITHMS);
            signer.initVerify(loadPublicKey(publicKeyBytes));
            signer.update(data);
            return signer.verify(encodeDer(sig));
        } catch (Exception e) {
            System.out.println("verifySig: " + e.getMessage());
            return false;
        }
    }

    public static PublicKey loadPublicKey(byte[] data) throws GeneralSecurityException {
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM, "SC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        ECCurve eccCurve = spec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(eccCurve, spec.getSeed());
        java.security.spec.ECPoint point = ECPointUtil.decodePoint(ellipticCurve, data);
        java.security.spec.ECParameterSpec params = EC5Util.convertSpec(ellipticCurve, spec);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, params);
        return factory.generatePublic(keySpec);
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws GeneralSecurityException {
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM, "SC");
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        ECCurve eccCurve = spec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(eccCurve, spec.getSeed());
        java.security.spec.ECParameterSpec params = EC5Util.convertSpec(ellipticCurve, spec);
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(new BigInteger(1, data), params);
        return factory.generatePrivate(keySpec);
    }

    private static byte[] decodeDer(byte[] data) {
        try {
            ASN1Sequence s = (ASN1Sequence) ASN1Primitive.fromByteArray(data);
            BigInteger[] sig = new BigInteger[2];
            sig[0] = ASN1Integer.getInstance(s.getObjectAt(0)).getValue();
            sig[1] = ASN1Integer.getInstance(s.getObjectAt(1)).getValue();
            byte[] array1 = sig[0].toByteArray();
            if (array1.length != 32) return new byte[]{};
            byte[] array2 = sig[1].toByteArray();
            if (array2.length != 32) return new byte[]{};
            return byteMerger(array1, array2);
        } catch (Exception e) {
            System.out.println("decodeDer error！！" + e.getMessage());
        }
        return new byte[]{};
    }

    private static byte[] encodeDer(byte[] dataDer) {
        BigInteger r = new BigInteger(1, extractBytes(dataDer, 0, 32));
        BigInteger s = new BigInteger(1, extractBytes(dataDer, 32, 32));
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new org.bouncycastle.asn1.ASN1Integer(r));
        v.add(new org.bouncycastle.asn1.ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            e.printStackTrace();
            return new byte[]{};
        }
    }

    private static byte[] extractBytes(byte[] src, int offset, int length) {
        byte[] bytes = new byte[length];
        System.arraycopy(src, offset, bytes, 0, bytes.length);
        return bytes;
    }

    //System.arraycopy()方法
    public static byte[] byteMerger(byte[] bt1, byte[] bt2) {
        byte[] bt3 = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }

}