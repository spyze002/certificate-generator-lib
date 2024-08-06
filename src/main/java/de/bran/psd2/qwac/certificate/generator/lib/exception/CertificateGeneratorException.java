

package de.bran.psd2.qwac.certificate.generator.lib.exception;

public class CertificateGeneratorException extends RuntimeException {

    private static final long serialVersionUID = 1608302175475740417L;

    public CertificateGeneratorException(String message) {
        super(message);
    }

    public CertificateGeneratorException(String message, Throwable cause) {
        super(message, cause);
    }

}
