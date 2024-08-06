

package de.bran.psd2.qwac.certificate.generator.lib.model;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;

public class SubjectData {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private X500Name x500name;
    private Integer serialNumber;
    private Date startDate;
    private Date endDate;
    private boolean ocspCheckNeeded;

    public SubjectData(PrivateKey privateKey, PublicKey publicKey, X500Name x500name, Integer serialNumber, Date startDate, Date endDate, boolean ocspCheckNeeded) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.x500name = x500name;
        this.serialNumber = serialNumber;
        this.startDate = startDate;
        this.endDate = endDate;
        this.ocspCheckNeeded = ocspCheckNeeded;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public X500Name getX500name() {
        return x500name;
    }

    public Integer getSerialNumber() {
        return serialNumber;
    }

    public Date getStartDate() {
        return startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public boolean isOcspCheckNeeded() {
        return ocspCheckNeeded;
    }
}
