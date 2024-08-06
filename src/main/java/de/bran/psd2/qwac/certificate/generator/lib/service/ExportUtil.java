
package de.bran.psd2.qwac.certificate.generator.lib.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringWriter;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import de.bran.psd2.qwac.certificate.generator.lib.exception.CertificateGeneratorException;

public class ExportUtil {

    private ExportUtil() {
    }

    public static String exportToString(Object obj) {
        try (StringWriter writer = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(obj);
            pemWriter.flush();
            return writer.toString().replace("\n", "");
        } catch (IOException ex) {
            throw new CertificateGeneratorException("Could not export certificate", ex);
        }
    }
    public static byte[] exportToBytes(Object obj) {
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
             JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(byteStream))) {
            pemWriter.writeObject(obj);
            pemWriter.flush();
            return byteStream.toByteArray();
        } catch (IOException ex) {
            throw new CertificateGeneratorException("Could not export certificate to bytes", ex);
        }
    }
}
