package com.daedafusion.crypto;

import com.daedafusion.crypto.certs.X500Builder;
import com.daedafusion.crypto.certs.impl.BouncyCastleCertCrypto;
import com.daedafusion.crypto.keys.KeyGenUtil;
import org.apache.log4j.Logger;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

/**
 * Created by mphilpot on 7/1/14.
 */
public class CertTest
{
    private static final Logger log = Logger.getLogger(CertTest.class);

    @Test
    public void testNameBuilder()
    {
        X500Builder builder = new X500Builder();

        builder.city("a").country("b").organization("c").orgUnit("d").state("e").commonName("f");

        String name = builder.build();

        assertThat(name, is("L=a,C=b,O=c,OU=d,ST=e,CN=f"));
    }

    @Test
    public void testSelfSign() throws Exception
    {
        Crypto.getProperty("somevalue");
        KeyPair kp = KeyGenUtil.generateKeyPair();

        X500Builder builder = new X500Builder();
        builder.commonName("localhost");

        byte[] cert = BouncyCastleCertCrypto.selfSign(kp, new X500Principal(builder.build()));

        InputStream in = new ByteArrayInputStream(cert);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate xCert = (X509Certificate) certificateFactory.generateCertificate(in);

        assertThat(xCert.getSubjectX500Principal().getName(), is("CN=localhost"));
        assertThat(xCert.getIssuerX500Principal().getName(), is("CN=localhost"));
    }
}
