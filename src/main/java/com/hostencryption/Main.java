package com.hostencryption;

import com.hostencryption.model.RequestData;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, URISyntaxException {
        File file = new File(Main.class.getClassLoader().getResource("certificate.pem").getFile());
        Encryptor encryptor =  Encryptor.New(file.getAbsolutePath());
        RequestData data = encryptor.generateEncryptedPayload("{\"Parameter1\":\"Value1\",\"Parameter2\":\"Value2\",\"Parameter3\":\"Value3\"}", "network specific");
        System.out.println(data);

    }
}
