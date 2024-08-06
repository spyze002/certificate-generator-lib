
package de.bran.psd2.qwac.certificate.generator.lib.model;

import java.security.PrivateKey;

import org.bouncycastle.asn1.x500.X500Name;

public class IssuerData {
    private X500Name x500name;
    private PrivateKey privateKey;

    public X500Name getX500name() {
        return x500name;
    }

    public void setX500name(X500Name x500name) {
        this.x500name = x500name;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
