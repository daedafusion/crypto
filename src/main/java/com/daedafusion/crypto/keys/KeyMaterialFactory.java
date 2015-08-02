package com.daedafusion.crypto.keys;

import com.daedafusion.crypto.Crypto;

/**
 * Created by mphilpot on 6/30/14.
 */
public class KeyMaterialFactory
{
    private static KeyMaterialFactory ourInstance = new KeyMaterialFactory();

    public static KeyMaterialFactory getInstance()
    {
        return ourInstance;
    }

    private KeyMaterialFactory()
    {
    }

    public KeyMaterial getKeyMaterial() throws KeyMaterialException
    {
        String providerClass = Crypto.getProperty(Crypto.KEY_MATERIAL_PROVIDER);

        try
        {
            KeyMaterial km = (KeyMaterial) Class.forName(providerClass).newInstance();

            km.init();

            return km;
        }
        catch (ClassNotFoundException | InstantiationException | IllegalAccessException e)
        {
            throw new KeyMaterialException(e);
        }
    }
}
