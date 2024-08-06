
package de.bran.psd2.qwac.certificate.generator.lib.model;


import java.util.ArrayList;
import java.util.List;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class CertificateRequest {

    @NotNull
    private String authorizationNumber;

    @Size(min = 1, max = 3)
    @NotNull
    private List<PspRole> roles = new ArrayList<>();
    @NotNull
    private String organizationName;

    private String organizationUnit;

    private String domainComponent;

    private String localityName;

    private String stateOrProvinceName;

    private String countryCode;

    @Min(-365)
    @Max(365)
    @NotNull
    private int validity;

    @NotNull
    private String commonName;

    @SuppressWarnings("PMD.RedundantFieldInitializer")
    private boolean ocspCheckNeeded = false;

    public CertificateRequest() {
    }

    public CertificateRequest(String authorizationNumber, List<PspRole> roles, String organizationName, String organizationUnit,
                              String domainComponent, String localityName, String stateOrProvinceName, String countryCode,
                              int validity, String commonName, boolean ocspCheckNeeded) {
        this.authorizationNumber = authorizationNumber;
        this.roles = roles;
        this.organizationName = organizationName;
        this.organizationUnit = organizationUnit;
        this.domainComponent = domainComponent;
        this.localityName = localityName;
        this.stateOrProvinceName = stateOrProvinceName;
        this.countryCode = countryCode;
        this.validity = validity;
        this.commonName = commonName;
        this.ocspCheckNeeded = ocspCheckNeeded;
    }

    public String getAuthorizationNumber() {
        return authorizationNumber;
    }

    public List<PspRole> getRoles() {
        return roles;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public String getDomainComponent() {
        return domainComponent;
    }

    public String getLocalityName() {
        return localityName;
    }

    public String getStateOrProvinceName() {
        return stateOrProvinceName;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public int getValidity() {
        return validity;
    }

    public String getCommonName() {
        return commonName;
    }

    public boolean isOcspCheckNeeded() {
        return ocspCheckNeeded;
    }
}
