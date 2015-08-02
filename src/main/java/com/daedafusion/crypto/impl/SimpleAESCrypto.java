package com.daedafusion.crypto.impl;

import com.daedafusion.crypto.Crypto;
import com.daedafusion.crypto.CryptoException;
import com.daedafusion.crypto.SymCrypto;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * Created by mphilpot on 6/30/14.
 */
public class SimpleAESCrypto implements SymCrypto
{
    private static final Logger log = Logger.getLogger(SimpleAESCrypto.class);

    private Key secret;
    private String algo;

    public SimpleAESCrypto(Key secret)
    {
        this.secret = secret;
        algo = Crypto.getProperty(Crypto.SYM_ALGO, "AES/CBC/PKCS5Padding");
    }

    @Override
    public byte[] encrypt(byte[] plainText, byte[] iv) throws CryptoException
    {
        try
        {
            Cipher cipher = Cipher.getInstance(algo);
            cipher.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));

            return cipher.doFinal(plainText);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException e)
        {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherText, byte[] iv) throws CryptoException
    {
        try
        {
            Cipher cipher = Cipher.getInstance(algo);
            cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

            return cipher.doFinal(cipherText);
        }
        catch (NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e)
        {
            throw new CryptoException(e);
        }
    }

    @Override
    public String encryptMessage(String plainText) throws CryptoException
    {
        byte[] iv = new byte[16]; // for AES-128
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);

        byte[] cipherText = encrypt(plainText.getBytes(), iv);

        return String.format("%s|%s", Base64.encodeBase64String(iv), Base64.encodeBase64String(cipherText));
    }

    @Override
    public String decryptMessage(String encodedCiperText) throws CryptoException
    {
        String[] components = encodedCiperText.split("\\|");

        if(components.length != 2)
        {
            throw new CryptoException("Invalid message");
        }

        return new String(decrypt(Base64.decodeBase64(components[1]), Base64.decodeBase64(components[0])));
    }
}
