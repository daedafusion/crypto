package com.daedafusion.crypto.certs;

/**
 * Created by mphilpot on 7/1/14.
 */
public class CertCryptoFactory
{
    private static CertCryptoFactory ourInstance = new CertCryptoFactory();

    public static CertCryptoFactory getInstance()
    {
        return ourInstance;
    }

    private CertCryptoFactory()
    {
    }

    public CertCrypto get()
    {
        return null;
    }
}
