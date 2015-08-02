package com.daedafusion.crypto;

import com.daedafusion.crypto.keys.KeyMaterial;
import com.daedafusion.crypto.keys.KeyMaterialException;
import com.daedafusion.crypto.keys.KeyMaterialFactory;
import com.daedafusion.crypto.keys.impl.ClasspathKeyStoreProvider;
import com.daedafusion.crypto.keys.impl.FileSystemKeyStoreProvider;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by mphilpot on 7/1/14.
 */
public class KeyMaterialTest
{
    private static final Logger log = Logger.getLogger(KeyMaterialTest.class);

    @After
    public void after()
    {
        System.clearProperty("keyStorePath");
        System.clearProperty("keyMaterialProvider");
    }

    @Test(expected=KeyMaterialException.class)
    public void noExistingKeystoreClasspath() throws KeyMaterialException
    {
        System.setProperty("keyStorePath", "unknown");
        System.setProperty("keyMaterialProvider", ClasspathKeyStoreProvider.class.getName());

        KeyMaterial km = KeyMaterialFactory.getInstance().getKeyMaterial();
    }

    @Test(expected=KeyMaterialException.class)
    public void noExistingKeystoreFileSystem() throws KeyMaterialException
    {
        System.setProperty("keyStorePath", "unknown");
        System.setProperty("keyMaterialProvider", FileSystemKeyStoreProvider.class.getName());

        KeyMaterial km = KeyMaterialFactory.getInstance().getKeyMaterial();
    }

    @Test
    public void classpathKeystore() throws KeyMaterialException
    {
        KeyMaterial km = KeyMaterialFactory.getInstance().getKeyMaterial();

        assertThat(km.aliases().size(), is(2));
        assertThat(km.aliases(), hasItem("systemaes"));
        assertThat(km.aliases(), hasItem("signingcert"));
    }
}
