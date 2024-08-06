/*
 * Copyright (c) 2018-2023 adorsys GmbH and Co. KG
 * All rights are reserved.
 */

package de.adorsys.psd2.qwac.certificate.generator.lib;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import de.bran.psd2.qwac.certificate.generator.lib.service.CertificateService;

public class CertificateGeneratorAppIT {

    @SuppressWarnings("squid:S2699") // Suppress "Tests should include assertions" Sonar rule
    @Disabled
    @Test
    void testApplicationStarts() {
        try {
            // Directly call the main method of the application class
            CertificateService.main(new String[]{});
            // If no exception is thrown, the application starts successfully
        } catch (Exception e) {
            e.printStackTrace();
            // If an exception is thrown, the application did not start successfully
            throw new RuntimeException("Application failed to start", e);
        }
    }
}
