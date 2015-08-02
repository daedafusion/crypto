package com.daedafusion.crypto.keys.impl;

import com.daedafusion.crypto.Crypto;
import com.daedafusion.crypto.keys.KeyMaterialException;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by mphilpot on 6/30/14.
 */
public class ClasspathKeyStoreProvider extends AbstractKeyStoreProvider
{
    private static final Logger log = Logger.getLogger(ClasspathKeyStoreProvider.class);

    private String keyStorePath;

    public ClasspathKeyStoreProvider()
    {
        keyStorePath = Crypto.getProperty(Crypto.KEYSTORE_PATH);
    }

    @Override
    public void init() throws KeyMaterialException
    {
        try
        {
            keyStore = KeyStore.getInstance(Crypto.getProperty(Crypto.KEYSTORE_TYPE));

            if(keyStorePath == null)
            {
                throw new KeyMaterialException("No specified keystore");
            }

            InputStream in = ClasspathKeyStoreProvider.class.getClassLoader().getResourceAsStream(keyStorePath);

            if(in == null)
            {
                throw new KeyMaterialException(String.format("KeyStore %s not found on classpath", keyStorePath));
            }

            keyStore.load(in, Crypto.getProperty(Crypto.KEYSTORE_PASSWORD).toCharArray());
        }
        catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    @Override
    public void save()
    {
        throw new UnsupportedOperationException("read-only keystore");
    }

    @Override
    public void addKey(String alias, Key key)
    {
        throw new UnsupportedOperationException("read-only keystore");
    }

    @Override
    public void addCertificate(String alias, X509Certificate cert, KeyPair key)
    {
        throw new UnsupportedOperationException("read-only keystore");
    }

    @Override
    public void addCertificate(String alias, X509Certificate cert)
    {
        throw new UnsupportedOperationException("read-only keystore");
    }
}
