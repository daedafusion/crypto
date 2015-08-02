package com.daedafusion.crypto.certs.impl;

import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.certs.CertCrypto;
import com.daedafusion.crypto.keys.KeyMaterial;
import com.daedafusion.crypto.keys.KeyMaterialException;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by mphilpot on 7/1/14.
 */
public class BouncyCastleCertCrypto implements CertCrypto
{
    private static final Logger log = Logger.getLogger(BouncyCastleCertCrypto.class);

    private final KeyMaterial km;

    public BouncyCastleCertCrypto(KeyMaterial km)
    {
        this.km = km;
    }

    @Override
    public byte[] generateCSR(KeyPair key, X500Principal principal) throws CryptoException
    {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(principal.getName()), key.getPublic());
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC");

        try
        {
            PKCS10CertificationRequest request = builder.build(signerBuilder.build(key.getPrivate()));

            return request.getEncoded();
        }
        catch (OperatorCreationException | IOException e)
        {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] signCSR(byte[] csr, String alias, Long startDate, Long endDate, BigInteger serialNumber) throws CryptoException
    {
        try
        {
            PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);

            X509Certificate caCert = km.getCertificate(alias);
            KeyPair keyPair = km.getKeyPair(alias);

            X509CertificateHolder authorityHolder = new JcaX509CertificateHolder(caCert);

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    authorityHolder.getSubject(), // issuer
                    serialNumber, // serial number
                    new Date(startDate),
                    new Date(endDate),
                    request.getSubject(),
                    caCert.getPublicKey()
            );

            JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC");

            X509CertificateHolder newCert = builder.build(signerBuilder.build(keyPair.getPrivate()));

            return newCert.getEncoded();
        }
        catch (IOException | KeyMaterialException | CertificateEncodingException | OperatorCreationException e)
        {
            throw new CryptoException(e);
        }
    }

    public static byte[] selfSign(KeyPair keyPair, X500Principal principal) throws Exception
    {
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(principal.getName()), keyPair.getPublic());
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC");
        PKCS10CertificationRequest csrRequest = builder.build(signerBuilder.build(keyPair.getPrivate()));

        byte[] csr = csrRequest.getEncoded();

        PKCS10CertificationRequest request = new PKCS10CertificationRequest(csr);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(principal.getName()), // issuer
                BigInteger.ONE, // serial number
                new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000),
                new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000),
                request.getSubject(),
                keyPair.getPublic()
        );

        signerBuilder = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC");

        X509CertificateHolder newCert = certBuilder.build(signerBuilder.build(keyPair.getPrivate()));

        return newCert.getEncoded();
    }
}
