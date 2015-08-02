package com.daedafusion.crypto;

/**
 * Created by mphilpot on 6/30/14.
 */
public interface SymCrypto
{
    byte[] encrypt(byte[] plainText, byte[] iv) throws CryptoException;
    byte[] decrypt(byte[] cipherText, byte[] iv) throws CryptoException;

    String encryptMessage(String plainText) throws CryptoException;
    String decryptMessage(String encodedCiperText) throws CryptoException;
}
