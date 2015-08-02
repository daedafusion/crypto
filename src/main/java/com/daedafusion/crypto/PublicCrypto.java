package com.daedafusion.crypto;

/**
 * Created by mphilpot on 6/30/14.
 */
public interface PublicCrypto
{
    byte[] encrypt(byte[] plainText) throws CryptoException;
    byte[] decrypt(byte[] cipherText) throws CryptoException;

    byte[] sign(byte[] contents) throws CryptoException;

    boolean verify(byte[] signature, byte[] contents) throws CryptoException;
}
