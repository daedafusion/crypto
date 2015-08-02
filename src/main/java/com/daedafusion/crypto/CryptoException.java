package com.daedafusion.crypto;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 6/30/14.
 */
public class CryptoException extends Exception
{
    private static final Logger log = Logger.getLogger(CryptoException.class);

    public CryptoException(String message)
    {
        super(message);
    }

    public CryptoException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public CryptoException(Throwable cause)
    {
        super(cause);
    }
}
