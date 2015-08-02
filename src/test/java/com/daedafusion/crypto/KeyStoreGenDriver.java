package com.daedafusion.crypto;

import com.daedafusion.crypto.certs.impl.BouncyCastleCertCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import com.daedafusion.crypto.keys.KeyMaterial;
import com.daedafusion.crypto.keys.impl.FileSystemKeyStoreProvider;
import org.apache.log4j.Logger;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by mphilpot on 7/1/14.
 */
public class KeyStoreGenDriver
{
    private static final Logger log = Logger.getLogger(KeyStoreGenDriver.class);

    public static void main(String[] args) throws Exception
    {
        KeyMaterial km = new FileSystemKeyStoreProvider(true);
        km.init();

        String name = "test.keystore";

        Key k = KeyGenUtil.generateSecretKey();
        KeyPair kp = KeyGenUtil.generateKeyPair();

        // Self sign Cert
        byte[] cert = BouncyCastleCertCrypto.selfSign(kp, new X500Principal("CN=localhost"));

        InputStream in = new ByteArrayInputStream(cert);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate xCert = (X509Certificate) certificateFactory.generateCertificate(in);

        km.addKey(Crypto.getProperty(Crypto.SYM_KEY_ALIAS), k);
        km.addCertificate(Crypto.getProperty(Crypto.SIGNING_CERT_ALIAS), xCert, kp);

        km.save();
    }
}
