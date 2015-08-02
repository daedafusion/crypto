package com.daedafusion.crypto.keys.impl;

import com.daedafusion.crypto.Crypto;
import com.daedafusion.crypto.keys.KeyMaterial;
import com.daedafusion.crypto.keys.KeyMaterialException;
import org.apache.log4j.Logger;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Created by mphilpot on 6/30/14.
 */
public abstract class AbstractKeyStoreProvider implements KeyMaterial
{
    private static final Logger log = Logger.getLogger(AbstractKeyStoreProvider.class);

    protected KeyStore keyStore;

    protected AbstractKeyStoreProvider()
    {

    }

    @Override
    public KeyStore getKeyStore()
    {
        return keyStore;
    }

    @Override
    public List<String> aliases() throws KeyMaterialException
    {
        try
        {
            return Collections.list(keyStore.aliases());
        }
        catch (KeyStoreException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    @Override
    public Key getKey(String alias) throws KeyMaterialException
    {
        try
        {
            return keyStore.getKey(alias, Crypto.getProperty(Crypto.PROTECTION_PASSWORD).toCharArray());
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    @Override
    public X509Certificate getCertificate(String alias) throws KeyMaterialException
    {
        try
        {
            return (X509Certificate) keyStore.getCertificate(alias);
        }
        catch (KeyStoreException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    @Override
    public KeyPair getKeyPair(String alias) throws KeyMaterialException
    {
        try
        {
            Key key = keyStore.getKey(alias, Crypto.getProperty(Crypto.PROTECTION_PASSWORD).toCharArray());

            if(key instanceof PrivateKey)
            {
                java.security.cert.Certificate cert = keyStore.getCertificate(alias);
                PublicKey pk = cert.getPublicKey();

                return new KeyPair(pk, (PrivateKey) key);
            }
            else
            {
                throw new KeyMaterialException(String.format("Alias %s was not a key pair", alias));
            }
        }
        catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e)
        {
            throw new KeyMaterialException(e);
        }
    }
}
