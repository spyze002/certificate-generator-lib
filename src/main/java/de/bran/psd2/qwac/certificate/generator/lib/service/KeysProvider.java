

package de.bran.psd2.qwac.certificate.generator.lib.service;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.util.X509CertUtils;

import de.bran.psd2.qwac.certificate.generator.lib.exception.CertificateGeneratorException;

public class KeysProvider {

    private static final Logger logger = LoggerFactory.getLogger(CertificateService.class);

    private String issuerPrivateKey;
    private String issuerCertificate;

    public KeysProvider(String issuerPrivateKey, String issuerCertificate){
        this.issuerPrivateKey = issuerPrivateKey;
        this.issuerCertificate = issuerCertificate;
    }

    public KeysProvider() {
        Properties properties = new Properties();
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream("application.yml")) {
            if (input == null) {
                throw new FileNotFoundException("application.yml not found in classpath");
            }
            properties.load(input);
            issuerPrivateKey = properties.getProperty("qwac.certificate-generator.template.public.key", "certificates/MyRootCA.key");
            issuerCertificate = properties.getProperty("qwac.certificate-generator.template.private.key", "certificates/MyRootCA.pem");

            logger.info("public key and private key properties load successfully");
        } catch (IOException e) {
            logger.error("Error loading public and private key property : {}", e.getMessage(), e);
        }
    }


    /**
     * Load private key from classpath.
     *
     * @return PrivateKey
     */
    public PrivateKey loadPrivateKey() {
        try (InputStream stream = Thread.currentThread().getContextClassLoader().getResourceAsStream(issuerPrivateKey);
             BufferedReader br = new BufferedReader(new InputStreamReader(stream));
             PEMParser pp = new PEMParser(br)) {

            Security.addProvider(new BouncyCastleProvider());
            PEMKeyPair pemKeyPair = (PEMKeyPair) pp.readObject();
            KeyPair kp = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
            return kp.getPrivate();
        } catch (IOException ex) {
            throw new CertificateGeneratorException("Could not load private key", ex);
        }
    }

    /**
     * Load X509Certificate from classpath.
     *
     * @return X509Certificate
     */
    public X509Certificate loadCertificate() {
        try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(issuerCertificate)) {
            byte[] bytes = IOUtils.toByteArray(is);
            return X509CertUtils.parse(bytes);
        } catch (IOException ex) {
            throw new CertificateGeneratorException("Could not read certificate from classpath", ex);
        }
    }

}

