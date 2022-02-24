package com.hostencryption.cryptoutils;

import com.hostencryption.Main;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class CryptoUtilsTest extends TestCase {


    public void testGetPublicKeyFromCertificate() throws FileNotFoundException, CertificateException {

        PublicKey key = CryptoUtils.getPublicKeyFromCertificate(getCertificateFilePath());

        String expected = "042E3E5CCF6B9AB04BE7A22F3FACCFDE73C87E87155394A34815408A896CA18A374DAC669AF3BF6220FC863767F4AF47507C5BC221FC4A19874DAF39B4074E3EB8";

        final SubjectPublicKeyInfo subjectPublicKeyInfo =  SubjectPublicKeyInfo.getInstance(key.getEncoded());
        String actual = Hex.toHexString(subjectPublicKeyInfo.getPublicKeyData().getBytes()).toUpperCase();
        assertEquals(expected, actual);
    }

    public void testGenerateSharedSecret() throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException {
        PublicKey publicKey = CryptoUtils.getPublicKeyFromCertificate(getCertificateFilePath());
        PrivateKey privateKey = CryptoUtils.getPrivateKeyFromHexString("7EEE47DEE108A08EDD2BCD2BB762A543CA23EA96C9AF09AD54BEB9FA3CE1A026");
        byte[] sharedKey = CryptoUtils.generateSharedSecret(publicKey, privateKey);
        String expected = "A88B995FECBDF756515ED42BA53A6CCCA4F5936F69CF4D15352C94C592B347B1";
        assertEquals(expected, Hex.toHexString(sharedKey).toUpperCase());

    }

    public void testGenerateKDF() throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidKeyException {
        PublicKey publicKey = CryptoUtils.getPublicKeyFromCertificate(getCertificateFilePath());
        PrivateKey privateKey = CryptoUtils.getPrivateKeyFromHexString("7EEE47DEE108A08EDD2BCD2BB762A543CA23EA96C9AF09AD54BEB9FA3CE1A026");
        byte[] sharedKey = CryptoUtils.generateSharedSecret(publicKey, privateKey);
        PublicKey ephemeralPublicKey = CryptoUtils.getPublicKeyFromHexString("0499A6F42E83EA4F150A78780FFB562C9CDB9B7507BC5D28CBFBF8CC3EF0AF68B36E60CB10DB69127830F7F899492017089E3B73C83FCF0EBDF2C06B613C3F88B7");
        byte[] kdf = CryptoUtils.generateKDF(sharedKey, ephemeralPublicKey);
        String expected = "00000001A88B995FECBDF756515ED42BA53A6CCCA4F5936F69CF4D15352C94C592B347B10D69642D6165733235362D47434D4170706C650499A6F42E83EA4F150A78780FFB562C9CDB9B7507BC5D28CBFBF8CC3EF0AF68B36E60CB10DB69127830F7F899492017089E3B73C83FCF0EBDF2C06B613C3F88B7";
        assertEquals(expected, Hex.toHexString(kdf).toUpperCase());

    }

    public void testGenerateSharedAESKey() throws NoSuchAlgorithmException {
        byte[] key = CryptoUtils.generateAESKey(Hex.decode("00000001A88B995FECBDF756515ED42BA53A6CCCA4F5936F69CF4D15352C94C592B347B10D69642D6165733235362D47434D4170706C650499A6F42E83EA4F150A78780FFB562C9CDB9B7507BC5D28CBFBF8CC3EF0AF68B36E60CB10DB69127830F7F899492017089E3B73C83FCF0EBDF2C06B613C3F88B7"));
        String expected = "083080D3D0C521C02CD3AE2134363D09EA50DFF914677FAB9E22F18F9C28A3B9";
        assertEquals(expected, Hex.toHexString(key).toUpperCase());
    }

    public void testDoAESEncrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] key = Hex.decode("083080D3D0C521C02CD3AE2134363D09EA50DFF914677FAB9E22F18F9C28A3B9");
        byte[] encryptedData = CryptoUtils.doAESEncrypt(key, "{\"Parameter1\":\"Value1\",\"Parameter2\":\"Value2\",\"Parameter3\":\"Value3\"}");
        String expected = "E3EF6BA2FFA05B6985FE129E3CB6845C4EA1E94AE98D31A538A4E24906FB720D764D640894CD9DE7CEC00114396651A1CCAEDCF480C57A959E925C04492B9CF85FC711FAB3CBED10DC2BA99A2BB063CEFF8DE1";
        assertEquals(expected, Hex.toHexString(encryptedData).toUpperCase());

    }

    public void testBase64Encode() {
        assertEquals("bmV0d29yayBzcGVjaWZpYw==", CryptoUtils.base64Encode("network specific".getBytes(StandardCharsets.UTF_8)));
        assertEquals("BJmm9C6D6k8VCnh4D/tWLJzbm3UHvF0oy/v4zD7wr2izbmDLENtpEngw9/iZSSAXCJ47c8g/zw698sBrYTw/iLc=", CryptoUtils.base64Encode(Hex.decode("0499A6F42E83EA4F150A78780FFB562C9CDB9B7507BC5D28CBFBF8CC3EF0AF68B36E60CB10DB69127830F7F899492017089E3B73C83FCF0EBDF2C06B613C3F88B7")));
        assertEquals("4+9rov+gW2mF/hKePLaEXE6h6UrpjTGlOKTiSQb7cg12TWQIlM2d587AARQ5ZlGhzK7c9IDFepWeklwESSuc+F/HEfqzy+0Q3CupmiuwY87/jeE=", CryptoUtils.base64Encode(Hex.decode("E3EF6BA2FFA05B6985FE129E3CB6845C4EA1E94AE98D31A538A4E24906FB720D764D640894CD9DE7CEC00114396651A1CCAEDCF480C57A959E925C04492B9CF85FC711FAB3CBED10DC2BA99A2BB063CEFF8DE1")));
    }

    private String getCertificateFilePath() {
        File file = new File(Main.class.getClassLoader().getResource("certificate.pem").getFile());
        return file.getAbsolutePath();
    }
}