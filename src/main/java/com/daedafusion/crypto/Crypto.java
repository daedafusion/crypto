package com.daedafusion.crypto;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.Security;
import java.util.Properties;

/**
 * Created by mphilpot on 7/1/14.
 */
public class Crypto
{
    private static final Logger log = Logger.getLogger(Crypto.class);

    private static Properties properties = new Properties();

    private Crypto(){}

    static
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        InputStream in = null;
        try
        {
            String cryptoProperties = System.getProperty("cryptoProperties", "classpath:crypto.properties");

            if(cryptoProperties.startsWith("classpath:"))
            {
                in = Crypto.class.getClassLoader().getResourceAsStream(cryptoProperties.substring("classpath:".length()));
            }
            else
            {
                File f = new File(URI.create(cryptoProperties));
                in = new FileInputStream(f);
            }

            if (in != null)
                properties.load(in);
        }
        catch (IOException e)
        {
            log.warn("Unable to load crypto.properties", e);
        }
        finally
        {
            if (in != null)
            {
                try
                {
                    in.close();
                }
                catch (IOException e)
                {
                    log.warn("", e);
                }
            }
        }
    }

    public static final String KEY_MATERIAL_PROVIDER = "keyMaterialProvider";
    public static final String KEYSTORE_PASSWORD = "keyStorePassword";
    public static final String PROTECTION_PASSWORD = "protectionPassword";
    public static final String KEYSTORE_PATH = "keyStorePath";
    public static final String KEYSTORE_TYPE = "keyStoreType";

    public static final String SIGNING_CERT_ALIAS = "signingCertAlias";
    public static final String SERVICE_CERT_ALIAS = "serviceCertAlias";
    public static final String SYM_KEY_ALIAS = "symKeyAlias";

    public static final String SYM_ALGO = "symAlgo";
    public static final String PUBLIC_ALGO = "publicAlgo";
    public static final String SIGNING_ALGO = "signingAlgo";

    public static String getProperty(String key)
    {
        String value = System.getProperty(key);

        if(value == null)
        {
            value = properties.getProperty(key);
        }

        return value;
    }

    public static String getProperty(String key, String defaultValue)
    {
        String value = System.getProperty(key);

        if(value == null)
        {
            value = properties.getProperty(key, defaultValue);
        }

        return value;
    }
}
