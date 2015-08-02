package com.daedafusion.crypto.certs;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Created by mphilpot on 7/1/14.
 */
public class X500Builder
{
    private static final Logger log = Logger.getLogger(X500Builder.class);

    private X500NameBuilder builder;

    public X500Builder()
    {
        builder = new X500NameBuilder(new BCStrictStyle());
    }

    public String build()
    {
        return builder.build().toString();
    }

    public X500Builder country(String c)
    {
        builder.addRDN(BCStyle.C, c);
        return this;
    }

    public X500Builder state(String st)
    {
        builder.addRDN(BCStyle.ST, st);
        return this;
    }

    public X500Builder city(String l)
    {
        builder.addRDN(BCStyle.L, l);
        return this;
    }

    public X500Builder organization(String o)
    {
        builder.addRDN(BCStyle.O, o);
        return this;
    }

    public X500Builder orgUnit(String ou)
    {
        builder.addRDN(BCStyle.OU, ou);
        return this;
    }

    public X500Builder commonName(String cn)
    {
        builder.addRDN(BCStyle.CN, cn);
        return this;
    }
}
