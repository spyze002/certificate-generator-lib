/*
 * Copyright (c) 2018-2023 adorsys GmbH and Co. KG
 * All rights are reserved.
 */

package de.adorsys.psd2.qwac.certificate.generator.lib.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;

import de.bran.psd2.qwac.certificate.generator.lib.model.CertificateRequest;
import de.bran.psd2.qwac.certificate.generator.lib.model.CertificateResponse;
import de.bran.psd2.qwac.certificate.generator.lib.model.IssuerData;
import de.bran.psd2.qwac.certificate.generator.lib.model.PspRole;
import de.bran.psd2.qwac.certificate.generator.lib.service.CertificateService;
import de.bran.psd2.qwac.certificate.generator.lib.service.IssuerDataService;
import de.bran.psd2.qwac.certificate.generator.lib.service.KeysProvider;

class CertificateServiceTest {

    @Mock
    private IssuerDataService issuerDataService;

    @Mock
    private KeysProvider keysProvider;

    @Mock
    private Logger logger;

    @InjectMocks
    private CertificateService certificateService;

    // Assuming you have a field for the certificateService
    private CertificateService certificateGenerator = mock(CertificateService.class);

    @BeforeEach
    public void setUp() {
        certificateGenerator= new CertificateService(logger);
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testGenerateCertificate() {
       // Mock CertificateRequest
        CertificateRequest request = mock(CertificateRequest.class);
        when(request.getOrganizationName()).thenReturn("TestOrg");
        when(request.getCommonName()).thenReturn("TestCommonName");
        when(request.getRoles()).thenReturn(List.of(PspRole.AISP, PspRole.PISP, PspRole.PIISP));
        when(request.getAuthorizationNumber()).thenReturn("12345");
        when(request.getValidity()).thenReturn(365);

        // Mock IssuerData
        IssuerData issuerData = mock(IssuerData.class);
        when(issuerDataService.getIssuerData()).thenReturn(issuerData);
        when(issuerData.getX500name()).thenReturn(mock(X500Name.class));
        when(issuerData.getPrivateKey()).thenReturn(mock(PrivateKey.class));

        // Generate a certificate
        CertificateResponse response = certificateService.generateCertificate(request);

        assertNotNull(response);
        assertNotNull(response.encodedCert());
        assertNotNull(response.privateKey());
    }

    @Test
    public void testGenerateKeyPair() {
        KeyPair keyPair = certificateService.generateKeyPair();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void testGeneratePemFilesCerts_NullTppJsonFilePath() throws IOException {
        certificateService.generatePemFilesCerts(null, "targetFolder");

        verify(logger).error("TPP JSON file path is null or empty.");
    }

    @Test
    public void testGeneratePemFilesCerts_NullTargetFolder() throws IOException {
        certificateService.generatePemFilesCerts("tppJsonFilePath", null);

        verify(logger).error("Target folder is null or empty.");
    }

    @Disabled
    @Test
    void testGeneratePemFilesCerts_FileNotFound() throws IOException {
        when(certificateGenerator.getInputStream(anyString())).thenReturn(null);

        certificateGenerator.generatePemFilesCerts("tppJsonFilePath", "targetFolder");

        verify(logger).error("TPP JSON file not found: {}", "tppJsonFilePath");
    }

    @Disabled
    @Test
    void testGeneratePemFilesCerts_IOExceptionThrown() throws IOException {
        when(certificateGenerator.getInputStream(anyString())).thenThrow(new IOException("File read error"));

        IOException thrown = assertThrows(IOException.class, () -> {
            certificateGenerator.generatePemFilesCerts("tppJsonFilePath", "targetFolder");
        });

        verify(logger).error("Error reading the JSON file: {}", "File read error");
        assertEquals("File read error", thrown.getMessage());
    }

    @Disabled
    @Test
    void testGeneratePemFilesCerts_Success() throws IOException {
        InputStream mockStream = mock(InputStream.class);
        when(certificateGenerator.getInputStream(anyString())).thenReturn(mockStream);

        CertificateRequest mockRequest = mock(CertificateRequest.class);
        when(certificateGenerator.parseJsonFile(any(InputStream.class))).thenReturn(mockRequest);

        CertificateResponse mockResponse = mock(CertificateResponse.class);
        when(certificateGenerator.generateCertificate(any(CertificateRequest.class))).thenReturn(mockResponse);

        doNothing().when(certificateGenerator).savePemFiles(anyString(), any(CertificateResponse.class), anyString());

        certificateGenerator.generatePemFilesCerts("tppJsonFilePath", "targetFolder");

        verify(logger).info("Processing certificate generation ...");
        verify(logger).info("Certificate generated successfully");
        verify(certificateGenerator).savePemFiles("targetFolder", mockResponse, mockRequest.getAuthorizationNumber());
    }
}