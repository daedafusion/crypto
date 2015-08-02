package com.daedafusion.crypto.keys;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Created by mphilpot on 6/30/14.
 */
public interface KeyMaterial
{
    void init() throws KeyMaterialException;
    void save() throws KeyMaterialException;

    KeyStore getKeyStore();

    List<String> aliases() throws KeyMaterialException;

    Key getKey(String alias) throws KeyMaterialException;

    KeyPair getKeyPair(String alias) throws KeyMaterialException;
    X509Certificate getCertificate(String alias) throws KeyMaterialException;

    void addKey(String alias, Key key) throws KeyMaterialException;
    void addCertificate(String alias, X509Certificate cert, KeyPair key) throws KeyMaterialException;
    void addCertificate(String alias, X509Certificate cert) throws KeyMaterialException;
}
