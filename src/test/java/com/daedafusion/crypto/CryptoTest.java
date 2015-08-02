package com.daedafusion.crypto;

import com.daedafusion.crypto.keys.KeyMaterialException;
import org.apache.log4j.Logger;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by mphilpot on 6/30/14.
 */
public class CryptoTest
{
    private static final Logger log = Logger.getLogger(CryptoTest.class);

    @Test
    public void symTest() throws KeyMaterialException, CryptoException
    {
        SymCrypto sc = CryptoFactory.getInstance().getSymCrypto();

        String test = "This is a test of the emergency broadcast system";

        String cipher = sc.encryptMessage(test);

        log.info(cipher);
        assertThat(cipher, is(not(test)));

        String result = sc.decryptMessage(cipher);

        assertThat(result, is(test));
    }

    @Test
    public void pkTest() throws KeyMaterialException, CryptoException
    {
        PublicCrypto pc = CryptoFactory.getInstance().getPublicCrypto();

        String test = "This is a test of the emergency broadcast system";

        byte[] cipher = pc.encrypt(test.getBytes());

        assertThat(new String(cipher), is(not(test)));

        String result = new String(pc.decrypt(cipher));

        assertThat(result, is(test));

        byte[] sig = pc.sign(test.getBytes());

        boolean verified = pc.verify(sig, test.getBytes());

        assertTrue(verified);

        verified = pc.verify(sig, (test+" foobar").getBytes());

        assertFalse(verified);
    }
}
