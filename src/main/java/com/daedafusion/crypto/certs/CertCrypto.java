package com.daedafusion.crypto.certs;

import com.daedafusion.crypto.CryptoException;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;

/**
 * Created by mphilpot on 6/30/14.
 */
public interface CertCrypto
{
    /**
     *
     * @param key
     * @param principal
     * @return
     * @throws CryptoException
     */
    byte[] generateCSR(KeyPair key, X500Principal principal) throws CryptoException;

    byte[] signCSR(byte[] csr, String alias, Long startDate, Long endDate, BigInteger serialNumber) throws CryptoException;
}
