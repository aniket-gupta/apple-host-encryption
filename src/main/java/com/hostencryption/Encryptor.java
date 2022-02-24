package com.hostencryption;

import com.hostencryption.cryptoutils.CryptoUtils;
import com.hostencryption.model.RequestData;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;

public class Encryptor {

    private PublicKey publicKey;

    private Encryptor(final String certificatePath) throws FileNotFoundException, CertificateException {

        this.publicKey = CryptoUtils.getPublicKeyFromCertificate(certificatePath);

    }

    public static Encryptor New(final String certificatePath) throws FileNotFoundException, CertificateException {
        return new Encryptor(certificatePath);
    }

    public RequestData generateEncryptedPayload(final String payload, final String activationData) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

        final KeyPair keyPair = CryptoUtils.generateEphemeralKeyPair();
        final PrivateKey ephemeralPrivateKey = keyPair.getPrivate();
        final PublicKey ephemeralPublicKey = keyPair.getPublic();
        final byte[] sharedSecret = CryptoUtils.generateSharedSecret(this.publicKey, ephemeralPrivateKey);
        final byte[] kdf = CryptoUtils.generateKDF(sharedSecret, ephemeralPublicKey);
        final byte[] aesKEY = CryptoUtils.generateAESKey(kdf);
        final byte[] encryptedPayload = CryptoUtils.doAESEncrypt(aesKEY, payload);
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ephemeralPublicKey.getEncoded());
        byte[] encodedKey = subjectPublicKeyInfo.getPublicKeyData().getBytes();
        return new RequestData(
                CryptoUtils.base64Encode(activationData.getBytes(StandardCharsets.UTF_8)),
                CryptoUtils.base64Encode(encodedKey),
                CryptoUtils.base64Encode(encryptedPayload)
        );

    }


}
