package com.hostencryption.cryptoutils;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;
import java.util.Base64;


public class CryptoUtils {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static byte[] COUNTER = new byte[]{0x00, 0x00, 0x00, 0x01};
    private static byte ALGO_ID_LEN = 0x0D;
    private static byte[] ALGO_ID = new byte[]{0x69, 0x64, 0x2D, 0x61, 0x65, 0x73, 0x32,
            0x35, 0x36, 0x2D, 0x47, 0x43, 0x4D};
    private static byte[] PARTY_U_INFO = new byte[]{0x41, 0x70, 0x70, 0x6C, 0x65};
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final byte[] GCM_IV = new byte[GCM_IV_LENGTH];


    public static PublicKey getPublicKeyFromCertificate(String certificatePath) throws CertificateException, FileNotFoundException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(certificatePath);
        X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);
        return cer.getPublicKey();
    }

    public static KeyPair generateEphemeralKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static PublicKey getPublicKeyFromHexString(String hex) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        ECPoint w = getEcPoint(hex);
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
        KeyFactory fact = KeyFactory.getInstance("EC", "BC");
        ECCurve curve = params.getCurve();
        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
        java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(w, params2);
        return fact.generatePublic(keySpec);
    }

    private static ECPoint getEcPoint(String hex) {
        byte[] encodedKey = Hex.decode(hex);
        int keyLength = encodedKey.length;

        // The public key should be either 64 or 65 bytes, depending upon whether or not the 0x04 value has been prepended to it
        if (keyLength < 64 || keyLength > 65)
        {
            throw new RuntimeException("While reconstructing a public key the " +
                    "encoded public key is not between 64 and 65 bytes in length. Something is wrong!");
        }

        if (keyLength == 65 && encodedKey[0] != (byte) 4)
        {
            throw new RuntimeException("While reconstructing a public key the encoded " +
                    "public key is 65 bytes in length, but the first byte is not 0x04. Something is wrong!");
        }

        byte[] xBytes = null;
        byte[] yBytes = null;

        if (encodedKey[0] == (byte) 4)
        {
            xBytes = Arrays.copyOfRange(encodedKey, 1, 33);
            yBytes = Arrays.copyOfRange(encodedKey, 33, 65);
        }

        else
        {
            xBytes = Arrays.copyOfRange(encodedKey, 0, 32);
            yBytes = Arrays.copyOfRange(encodedKey, 32, 64);
        }

        BigInteger x = getUnsignedBigInteger(xBytes, 0, 32);
        BigInteger y = getUnsignedBigInteger(yBytes, 0, 32);


        ECPoint w = new ECPoint(x, y);
        return w;
    }

    public static PrivateKey getPrivateKeyFromHexString(String hex) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        byte[] encodedKey = Hex.decode(hex);
        BigInteger privateKeyDValue = new BigInteger(encodedKey);

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECCurve curve = params.getCurve();
        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
        java.security.spec.ECParameterSpec params2 = EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPrivateKeySpec keySpec = new java.security.spec.ECPrivateKeySpec(privateKeyDValue, params2);
        KeyFactory fact = KeyFactory.getInstance("EC", "BC");
        return fact.generatePrivate(keySpec);
    }

    public static byte[] generateSharedSecret(PublicKey publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }

    public static byte[] generateKDF(byte[] sharedSecret, PublicKey key) {
        final SubjectPublicKeyInfo subjectPublicKeyInfo =  SubjectPublicKeyInfo.getInstance(key.getEncoded());
        byte[] encodedKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        int lenKDF = COUNTER.length + sharedSecret.length + 1 + ALGO_ID.length + PARTY_U_INFO.length + encodedKey.length;
        byte[] kdf = new byte[lenKDF];
        int pos = 0;
        System.arraycopy(COUNTER, 0, kdf, pos, COUNTER.length);
        pos += COUNTER.length;
        System.arraycopy(sharedSecret, 0, kdf, pos, sharedSecret.length);
        pos += sharedSecret.length;
        kdf[pos++] = ALGO_ID_LEN;
        System.arraycopy(ALGO_ID, 0, kdf, pos, ALGO_ID.length);
        pos += ALGO_ID.length;
        System.arraycopy(PARTY_U_INFO, 0, kdf, pos, PARTY_U_INFO.length);
        pos += PARTY_U_INFO.length;
        System.arraycopy(encodedKey, 0, kdf, pos, encodedKey.length);
        return kdf;
    }

    public static byte[] generateAESKey(byte[] kdf) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(kdf);
    }

    public static byte[] doAESEncrypt(byte[] key, String payload) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, GCM_IV);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        return cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    }

    public static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }


    private static BigInteger getUnsignedBigInteger(byte[] data, int start, int length)
    {
        if (length == 0)
        {
            return BigInteger.ZERO;
        }

        byte[] value = new byte[length + 1];
        System.arraycopy(data, start, value, 1, length);

        return new BigInteger(value);
    }

}
