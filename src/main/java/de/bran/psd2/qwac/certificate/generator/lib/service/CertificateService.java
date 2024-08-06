
package de.bran.psd2.qwac.certificate.generator.lib.service;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

import de.bran.psd2.qwac.certificate.generator.lib.exception.CertificateGeneratorException;
import de.bran.psd2.qwac.certificate.generator.lib.model.CertificateRequest;
import de.bran.psd2.qwac.certificate.generator.lib.model.CertificateResponse;
import de.bran.psd2.qwac.certificate.generator.lib.model.IssuerData;
import de.bran.psd2.qwac.certificate.generator.lib.model.NcaId;
import de.bran.psd2.qwac.certificate.generator.lib.model.NcaName;
import de.bran.psd2.qwac.certificate.generator.lib.model.PspRole;
import de.bran.psd2.qwac.certificate.generator.lib.model.SubjectData;


public class CertificateService {
    private static final String NCA_SHORT_NAME = "FAKENCA";
    private static final ASN1ObjectIdentifier ETSI_QC_STATEMENT = new ASN1ObjectIdentifier("0.4.0.19495.2");
    private static final SecureRandom RANDOM = new SecureRandom();

    private Logger logger = LoggerFactory.getLogger(CertificateService.class);

    private IssuerDataService issuerDataService = getIssuerDataService();

    public CertificateService() {
        KeysProvider keysProvider = new KeysProvider();
        this.issuerDataService = new IssuerDataService(keysProvider);
    }

    public CertificateService(Logger logger) {
        this.logger = logger;
    }

    /**
     * Create a new base64 encoded X509 certificate for authentication at the XS2A API with the
     * corresponding private key and meta data.
     *
     * @param certificateRequest data needed for certificate generation
     * @return CertificateResponse base64 encoded cert + private key
     */
    public CertificateResponse generateCertificate(CertificateRequest certificateRequest) {
        SubjectData subjectData = generateSubjectData(certificateRequest);
        QCStatement qcStatement = generateQcStatement(certificateRequest);

        X509Certificate cert = generateCertificate(subjectData, qcStatement);

        return new CertificateResponse(ExportUtil.exportToString(cert), ExportUtil.exportToString(subjectData.getPrivateKey()));
    }

    /**
     * Generates PEM files for certificates based on a provided JSON file.
     * <p>
     * This method reads a JSON file containing a certificate request, processes the request to generate a certificate,
     * and then saves the generated certificate and private key as PEM files in the specified target folder.
     * </p>
     *
     * @param tppJsonFilePath the file path to the TPP JSON file containing the certificate request
     * @param targetFolder the directory where the PEM files will be saved
     */
    public void generatePemFilesCerts(String tppJsonFilePath, String targetFolder) throws IOException {
        if (tppJsonFilePath == null || tppJsonFilePath.isEmpty()) {
            logger.error("TPP JSON file path is null or empty.");
            return;
        }else if (targetFolder == null || targetFolder.isEmpty()) {
            logger.error("Target folder is null or empty.");
            return;
        }

        try (InputStream jsonFileStream = getInputStream(tppJsonFilePath)) {
            if (jsonFileStream == null) {
                logger.error("TPP JSON file not found: {}", tppJsonFilePath);
                return;
            }

            CertificateRequest request = parseJsonFile(jsonFileStream);

            logger.info("Processing certificate generation ...");
            CertificateResponse response = generateCertificate(request);

            logger.info("Certificate generated successfully");
            savePemFiles(targetFolder, response, request.getAuthorizationNumber());
        } catch (IOException e) {
            logger.error("Error reading the JSON file: {}", e.getMessage(), e);
            throw e;
        }
    }

     CertificateRequest parseJsonFile(InputStream jsonFileStream) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(jsonFileStream, CertificateRequest.class);
    }

    InputStream getInputStream(String tppJsonFilePath) {
        return Thread.currentThread().getContextClassLoader()
                .getResourceAsStream(Paths.get(tppJsonFilePath)
                        .getFileName().toString());
    }

    /**
     * Generates new X.509 Certificate
     *
     * @return X509Certificate
     */
    private X509Certificate generateCertificate(SubjectData subjectData, QCStatement statement) {
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        IssuerData issuerData = issuerDataService.getIssuerData();
        ContentSigner contentSigner;

        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuerData.getX500name(),
                                                                           new BigInteger(subjectData.getSerialNumber().toString()), subjectData.getStartDate(),
                                                                           subjectData.getEndDate(),
                                                                           subjectData.getX500name(), subjectData.getPublicKey());
        JcaX509CertificateConverter certConverter;

        try {
            contentSigner = builder.build(issuerData.getPrivateKey());
            certGen.addExtension(Extension.qCStatements, false, new DERSequence(new ASN1Encodable[]{statement}));

            if(!subjectData.isOcspCheckNeeded()) {
                Extension ocspExtension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, new DEROctetString(DERNull.INSTANCE));
                certGen.addExtension(ocspExtension);
            }


            X509CertificateHolder certHolder = certGen.build(contentSigner);

            certConverter = new JcaX509CertificateConverter();

            return certConverter.getCertificate(certHolder);
        } catch (Exception ex) {
            throw new CertificateGeneratorException("Could not create certificate", ex);
        }
    }

    private QCStatement generateQcStatement(CertificateRequest certificateRequest) {
        NcaName ncaName = getNcaNameFromIssuerData();
        NcaId ncaId = getNcaIdFromIssuerData();
        ASN1Encodable qcStatementInfo = createQcInfo(
            RolesOfPsp.fromCertificateRequest(certificateRequest), ncaName, ncaId
        );

        return new QCStatement(ETSI_QC_STATEMENT, qcStatementInfo);
    }

    private DERSequence createQcInfo(RolesOfPsp rolesOfPsp, NcaName ncaName, NcaId ncaId) {
        return new DERSequence(new ASN1Encodable[]{rolesOfPsp, ncaName, ncaId});
    }

    private NcaName getNcaNameFromIssuerData() {
        return new NcaName(IETFUtils.valueToString(
            issuerDataService.getIssuerData().getX500name().getRDNs(BCStyle.O)[0]
                .getFirst().getValue())
        );
    }

    private NcaId getNcaIdFromIssuerData() {
        String country = IETFUtils.valueToString(issuerDataService.getIssuerData()
                                                     .getX500name().getRDNs(BCStyle.C)[0]
                                                     .getFirst().getValue());
        return new NcaId(country + "-" + NCA_SHORT_NAME);
    }

    private SubjectData generateSubjectData(CertificateRequest cerData) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.O, cerData.getOrganizationName());
        if (StringUtils.isNotBlank(cerData.getCommonName())) {
            builder.addRDN(BCStyle.CN, cerData.getCommonName());
        }
        if (cerData.getDomainComponent() != null) {
            builder.addRDN(BCStyle.DC, cerData.getDomainComponent());
        }
        if (cerData.getOrganizationUnit() != null) {
            builder.addRDN(BCStyle.OU, cerData.getOrganizationUnit());
        }
        if (cerData.getCountryCode() != null) {
            builder.addRDN(BCStyle.C, cerData.getCountryCode());
        }
        if (cerData.getStateOrProvinceName() != null) {
            builder.addRDN(BCStyle.ST, cerData.getStateOrProvinceName());
        }
        if (cerData.getLocalityName() != null) {
            builder.addRDN(BCStyle.L, cerData.getLocalityName());
        }

        builder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, cerData.getAuthorizationNumber());

        Date expiration = Date.from(
            LocalDate.now().plusDays(cerData.getValidity()).atStartOfDay(ZoneOffset.UTC).toInstant()
        );
        KeyPair keyPairSubject = generateKeyPair();
        Integer serialNumber = RANDOM.nextInt(Integer.MAX_VALUE);
        return new SubjectData(
            keyPairSubject.getPrivate(), keyPairSubject.getPublic(), builder.build(),
            serialNumber, new Date(), expiration, cerData.isOcspCheckNeeded());
    }

    protected KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, SecureRandom.getInstance("SHA1PRNG", "SUN"));
            return keyGen.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new CertificateGeneratorException("Could not generate key pair", ex);
        }
    }

    private static class RolesOfPsp extends DERSequence {

        static RolesOfPsp fromCertificateRequest(CertificateRequest certificateRequest) {
            List<RoleOfPsp> roles = new ArrayList<>();

            List<PspRole> requestRoles = certificateRequest.getRoles();
            if (requestRoles.contains(PspRole.AISP)) {
                roles.add(RoleOfPsp.PSP_AI);
            }

            if (requestRoles.contains(PspRole.PISP)) {
                roles.add(RoleOfPsp.PSP_PI);
            }

            if (requestRoles.contains(PspRole.PIISP)) {
                roles.add(RoleOfPsp.PSP_IC);
            }

            if (requestRoles.contains(PspRole.ASPSP)) {
                roles.add(RoleOfPsp.PSP_AS);
            }

            return new RolesOfPsp(roles.toArray(new RoleOfPsp[]{}));
        }

        RolesOfPsp(RoleOfPsp... array) {
            super(array);
        }
    }

    private static class RoleOfPsp extends DERSequence {

        static final RoleOfPsp PSP_PI = new RoleOfPsp(RoleOfPspOid.ID_PSD_2_ROLE_PSP_PI,
                                                      RoleOfPspName.PSP_PI);
        static final RoleOfPsp PSP_AI = new RoleOfPsp(RoleOfPspOid.ID_PSD_2_ROLE_PSP_AI,
                                                      RoleOfPspName.PSP_AI);
        static final RoleOfPsp PSP_IC = new RoleOfPsp(RoleOfPspOid.ROLE_OF_PSP_OID,
                                                      RoleOfPspName.PSP_IC);
        static final RoleOfPsp PSP_AS = new RoleOfPsp(RoleOfPspOid.ID_PSD_2_ROLE_PSP_AS,
                                                      RoleOfPspName.PSP_AS);

        private RoleOfPsp(RoleOfPspOid roleOfPspOid, RoleOfPspName roleOfPspName) {
            super(new ASN1Encodable[]{roleOfPspOid, roleOfPspName});
        }
    }

    private static class RoleOfPspName extends DERUTF8String {
        static final RoleOfPspName PSP_PI = new RoleOfPspName("PSP_PI");
        static final RoleOfPspName PSP_AI = new RoleOfPspName("PSP_AI");
        static final RoleOfPspName PSP_IC = new RoleOfPspName("PSP_IC");
        static final RoleOfPspName PSP_AS = new RoleOfPspName("PSP_AS");

        private RoleOfPspName(String string) {
            super(string);
        }
    }

    private static class RoleOfPspOid extends ASN1ObjectIdentifier {

        static final ASN1ObjectIdentifier ETSI_PSD_2_ROLES = new ASN1ObjectIdentifier(
            "0.4.0.19495.1");
        static final RoleOfPspOid ID_PSD_2_ROLE_PSP_AS = new RoleOfPspOid(
            ETSI_PSD_2_ROLES.branch("1"));
        static final RoleOfPspOid ID_PSD_2_ROLE_PSP_PI = new RoleOfPspOid(
            ETSI_PSD_2_ROLES.branch("2"));
        static final RoleOfPspOid ID_PSD_2_ROLE_PSP_AI = new RoleOfPspOid(
            ETSI_PSD_2_ROLES.branch("3"));
        static final RoleOfPspOid ROLE_OF_PSP_OID = new RoleOfPspOid(
            ETSI_PSD_2_ROLES.branch("4"));

        RoleOfPspOid(ASN1ObjectIdentifier identifier) {
            super(identifier.getId());
        }
    }
        //this.logger = LoggerFactory.getLogger(CertificateService.class);

    IssuerDataService getIssuerDataService() {
        KeysProvider keysProvider = new KeysProvider();
        return new IssuerDataService(keysProvider);
    }

    private void saveCertificateAsPem(String targetFolder, String certificate, String pemFileName) throws IOException {
        Path targetPath = Paths.get(targetFolder);
        Files.createDirectories(targetPath);

        // Define the output filename
        Path filepath = targetPath.resolve(pemFileName);

        // Write the certificate to a pem file
        try (BufferedWriter writer = Files.newBufferedWriter(filepath)) {
            writer.write(certificate);
            logger.info("PEM file created: {}", filepath);
        } catch (IOException e) {
            logger.error("Error writing the certificate to PEM file: {}", filepath, e);
            throw e;
        }
    }

    void savePemFiles(String targetFolder, CertificateResponse response, String authNumber) throws IOException {
        StringBuilder certFileName = new StringBuilder(authNumber).append("-encodedCert.pem");
        StringBuilder keyFileName = new StringBuilder(authNumber).append("-privateKey.key");

        logger.info("Saving certificate to file: {}", certFileName);
        saveCertificateAsPem(targetFolder, response.encodedCert(), certFileName.toString());

        logger.info("Saving private key to file: {}", keyFileName);
        saveCertificateAsPem(targetFolder, response.privateKey(), keyFileName.toString());
    }

    public static void main(String[] args) {
        final int ARGS_SIZE = 1;
        Logger log = LoggerFactory.getLogger(CertificateService.class);
        try {
            // Check if the required arguments are provided
            if (args.length < ARGS_SIZE) {
                log.info("Usage: java CertificateService <path/to/yourTppFile.json> [--target_folder <target_folder>]");
                return;
            }

            String tppJsonFilePath = args[0];
            // Optional target folder argument
            String targetFolder = args.length > 1 && "--target_folder".equals(args[1]) ? args[2] : "certs";

            CertificateService certificateService = new CertificateService();

            certificateService.generatePemFilesCerts(tppJsonFilePath, targetFolder);
        } catch (IOException e) {
            log.error("An error occurred: {}", e.getMessage(), e);
        }
    }
}
