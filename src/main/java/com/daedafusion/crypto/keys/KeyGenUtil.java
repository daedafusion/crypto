package com.daedafusion.crypto.keys;

import org.apache.log4j.Logger;

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by mphilpot on 7/1/14.
 */
public class KeyGenUtil
{
    private static final Logger log = Logger.getLogger(KeyGenUtil.class);

    private KeyGenUtil(){}

    public static Key generateSecretKey() throws KeyMaterialException
    {
        try
        {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128);

            return kgen.generateKey();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new KeyMaterialException(e);
        }
    }

    public static KeyPair generateKeyPair() throws KeyMaterialException
    {
        try
        {
            KeyPairGenerator kgen = KeyPairGenerator.getInstance("RSA");
            kgen.initialize(2048);

            return kgen.generateKeyPair();
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new KeyMaterialException(e);
        }
    }
}
