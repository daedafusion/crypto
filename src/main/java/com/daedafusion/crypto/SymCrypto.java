package com.daedafusion.crypto;

/**
 * Created by mphilpot on 6/30/14.
 */
public interface SymCrypto
{
    /**
     * Encrypt bytes using supplied iv vector
     *
     * @param plainText
     * @param iv
     * @return
     * @throws CryptoException
     */
    byte[] encrypt(byte[] plainText, byte[] iv) throws CryptoException;

    /**
     * Decrypt bytes using the supplied iv vector
     *
     * @param cipherText
     * @param iv
     * @return
     * @throws CryptoException
     */
    byte[] decrypt(byte[] cipherText, byte[] iv) throws CryptoException;

    /**
     * Encrypt string using a random iv vector that is prepended to the result
     *
     * @param plainText
     * @return
     * @throws CryptoException
     */
    String encryptMessage(String plainText) throws CryptoException;

    /**
     * Decrypt string using the iv vector that is prepended to the cypher text
     *
     * @param encodedCiperText
     * @return
     * @throws CryptoException
     */
    String decryptMessage(String encodedCiperText) throws CryptoException;
}
