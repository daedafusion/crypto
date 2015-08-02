package com.daedafusion.crypto;

import com.daedafusion.crypto.impl.SimpleAESCrypto;
import com.daedafusion.crypto.impl.SimpleRSACrypto;
import com.daedafusion.crypto.keys.KeyMaterial;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.crypto.keys.KeyMaterialFactory;
import org.apache.log4j.Logger;

import java.security.KeyPair;
import java.security.KeyStore;

/**
 * Created by mphilpot on 6/30/14.
 */
public class CryptoFactory
{
    private static final Logger        log         = Logger.getLogger(CryptoFactory.class);

    private static       CryptoFactory ourInstance = new CryptoFactory();

    public static CryptoFactory getInstance()
    {
        return ourInstance;
    }

    private KeyMaterial km;

    protected CryptoFactory()
    {
    }

    private void initKM() throws KeyMaterialException
    {
        km = KeyMaterialFactory.getInstance().getKeyMaterial();
    }

    public PublicCrypto getPublicCrypto(KeyPair pair)
    {
        return new SimpleRSACrypto(pair);
    }

    public synchronized PublicCrypto getPublicCrypto() throws KeyMaterialException
    {
        return getPublicCrypto(Crypto.getProperty(Crypto.SIGNING_CERT_ALIAS));
    }

    public synchronized SymCrypto getSymCrypto() throws KeyMaterialException
    {
        return getSymCrypto(Crypto.getProperty(Crypto.SYM_KEY_ALIAS));
    }

    public synchronized PublicCrypto getPublicCrypto(String alias) throws KeyMaterialException
    {
        if(km == null)
        {
            initKM();
        }

        return new SimpleRSACrypto(km.getKeyPair(alias));
    }

    public synchronized SymCrypto getSymCrypto(String alias) throws KeyMaterialException
    {
        if(km == null)
        {
            initKM();
        }

        return new SimpleAESCrypto(km.getKey(alias));
    }

    public synchronized KeyStore getKeyStore() throws KeyMaterialException
    {
        if(km == null)
        {
            initKM();
        }

        return km.getKeyStore();
    }
}
