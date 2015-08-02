package com.daedafusion.crypto.keys.impl;

import com.daedafusion.crypto.Crypto;
import com.daedafusion.crypto.keys.KeyMaterialException;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Created by mphilpot on 7/1/14.
 */
public class FileSystemKeyStoreProvider extends AbstractKeyStoreProvider
{
    private static final Logger log = Logger.getLogger(FileSystemKeyStoreProvider.class);

    private String keyStorePath;
    private boolean create;

    public FileSystemKeyStoreProvider()
    {
        keyStorePath = Crypto.getProperty(Crypto.KEYSTORE_PATH);
        create = false;
    }

    public FileSystemKeyStoreProvider(boolean create)
    {
        this();
        this.create = create;
    }

    @Override
    public void init() throws KeyMaterialException
    {
        InputStream in = null;
        try
        {
            keyStore = KeyStore.getInstance(Crypto.getProperty(Crypto.KEYSTORE_TYPE));

            if(keyStorePath == null)
            {
                throw new KeyMaterialException("No specified keystore");
            }

            if(!create)
            {
                in = new FileInputStream(new File(keyStorePath));

                keyStore.load(in, Crypto.getProperty(Crypto.KEYSTORE_PASSWORD).toCharArray());
            }
            else
            {
                keyStore.load(null);
            }
        }
        catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e)
        {
            throw new KeyMaterialException(e);
        }
        finally
        {
            IOUtils.closeQuietly(in);
        }
    }

    @Override
    public void save() throws KeyMaterialException
    {
        OutputStream out = null;
        try
        {
            out = new FileOutputStream(new File(keyStorePath));
            keyStore.store(out, Crypto.getProperty(Crypto.KEYSTORE_PASSWORD).toCharArray());
        }
        catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e)
        {
            throw new KeyMaterialException(e);
        }
        finally
        {
            IOUtils.closeQuietly(out);
        }
    }

    @Override
    public void addKey(String alias, Key key) throws KeyMaterialException
    {
        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry((javax.crypto.SecretKey) key);
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(Crypto.getProperty(Crypto.PROTECTION_PASSWORD).toCharArray());

        try
        {
            keyStore.setEntry(alias, skEntry, protection);
        }
        catch (KeyStoreException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    @Override
    public void addCertificate(String alias, X509Certificate cert, KeyPair key) throws KeyMaterialException
    {
        java.security.cert.Certificate[] chain = new Certificate[1];
        chain[0] = cert;
        try
        {
            keyStore.setKeyEntry(alias, key.getPrivate(), Crypto.getProperty(Crypto.PROTECTION_PASSWORD).toCharArray(), chain);
        }
        catch (KeyStoreException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    @Override
    public void addCertificate(String alias, X509Certificate cert) throws KeyMaterialException
    {
        try
        {
            keyStore.setCertificateEntry(alias, cert);
        }
        catch (KeyStoreException e)
        {
            throw new KeyMaterialException(e);
        }
    }
}
