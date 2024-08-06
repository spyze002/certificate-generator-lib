
package de.bran.psd2.qwac.certificate.generator.lib.service;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import de.bran.psd2.qwac.certificate.generator.lib.exception.CertificateGeneratorException;
import de.bran.psd2.qwac.certificate.generator.lib.model.IssuerData;

public class IssuerDataService {

    private final KeysProvider keysProvider;
    private final IssuerData issuerData;


    public IssuerData getIssuerData() {
        return issuerData;
    }

    public IssuerDataService(KeysProvider keysProvider) {
        this.keysProvider = keysProvider;
        this.issuerData = generateIssuerData();
    }

    private IssuerData generateIssuerData() {
        IssuerData data = new IssuerData();
        X509Certificate cert = keysProvider.loadCertificate();

        try {
            data.setX500name(new JcaX509CertificateHolder(cert).getSubject());
        } catch (CertificateEncodingException ex) {
            throw new CertificateGeneratorException("Could not read issuer data from certificate", ex);
        }

        data.setPrivateKey(keysProvider.loadPrivateKey());

        return data;
    }
}
