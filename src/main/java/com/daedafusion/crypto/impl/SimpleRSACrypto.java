package com.daedafusion.crypto.impl;

import com.daedafusion.crypto.Crypto;
import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.PublicCrypto;
import org.apache.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.Certificate;

/**
 * Created by mphilpot on 6/30/14.
 */
public class SimpleRSACrypto implements PublicCrypto
{
    private static final Logger log = Logger.getLogger(SimpleRSACrypto.class);

    private KeyPair keyPair;
    private Certificate cert;

    private String algo;
    private String signAlgo;

    private SimpleRSACrypto()
    {
        algo = Crypto.getProperty(Crypto.PUBLIC_ALGO, "RSA/ECB/PKCS1Padding");
        signAlgo = Crypto.getProperty(Crypto.SIGNING_ALGO, "SHA1withRSA");
    }

    public SimpleRSACrypto(KeyPair keyPair)
    {
        this();
        this.keyPair = keyPair;
    }

    public SimpleRSACrypto(Certificate cert)
    {
        this();
        this.cert = cert;
    }


    @Override
    public byte[] encrypt(byte[] plainText) throws CryptoException
    {
        try
        {
            Cipher cipher = Cipher.getInstance(algo);
            if (keyPair != null)
            {
                cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            }
            else
            {
                cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
            }

            return cipher.doFinal(plainText);
        }
        catch (IllegalBlockSizeException | InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws CryptoException
    {
        try
        {
            Cipher cipher = Cipher.getInstance(algo);
            if(keyPair == null)
            {
                throw new CryptoException("Cannot decrypt without a key pair");
            }
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

            return cipher.doFinal(cipherText);
        }
        catch (IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException e)
        {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] sign(byte[] contents) throws CryptoException
    {
        if(keyPair == null)
        {
            throw new CryptoException("Cannot sign without a key pair");
        }

        try
        {
            Signature sig = Signature.getInstance(signAlgo);
            sig.initSign(keyPair.getPrivate());

            sig.update(contents);

            return sig.sign();
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e)
        {
            throw new CryptoException(e);
        }
    }

    @Override
    public boolean verify(byte[] signature, byte[] contents) throws CryptoException
    {
        try
        {
            Signature sig = Signature.getInstance(signAlgo);
            if(keyPair != null)
            {
                sig.initVerify(keyPair.getPublic());
            }
            else
            {
                sig.initVerify(cert);
            }

            sig.update(contents);

            return sig.verify(signature);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e)
        {
            throw new CryptoException(e);
        }
    }
}
