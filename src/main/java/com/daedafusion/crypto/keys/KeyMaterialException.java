package com.daedafusion.crypto.keys;

import org.apache.log4j.Logger;

/**
 * Created by mphilpot on 6/30/14.
 */
public class KeyMaterialException extends Exception
{
    private static final Logger log = Logger.getLogger(KeyMaterialException.class);

    public KeyMaterialException(String message)
    {
        super(message);
    }

    public KeyMaterialException(String message, Throwable cause)
    {
        super(message, cause);
    }

    public KeyMaterialException(Throwable cause)
    {
        super(cause);
    }
}
