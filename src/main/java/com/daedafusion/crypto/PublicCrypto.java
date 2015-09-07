package com.daedafusion.crypto;

/**
 * Created by mphilpot on 6/30/14.
 */
public interface PublicCrypto
{
    /**
     * Encrypt plain text bytes
     *
     * @param plainText
     * @return
     * @throws CryptoException
     */
    byte[] encrypt(byte[] plainText) throws CryptoException;

    /**
     * Decrypt cipher text bytes
     *
     * @param cipherText
     * @return
     * @throws CryptoException
     */
    byte[] decrypt(byte[] cipherText) throws CryptoException;

    /**
     * Generate digital signature for supplied contents
     *
     * @param contents
     * @return
     * @throws CryptoException
     */
    byte[] sign(byte[] contents) throws CryptoException;

    /**
     * Verify a digital signature for the given contents
     *
     * @param signature
     * @param contents
     * @return
     * @throws CryptoException
     */
    boolean verify(byte[] signature, byte[] contents) throws CryptoException;
}
