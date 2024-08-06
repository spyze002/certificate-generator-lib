## Certificate generator description

Certificate generator is a standalone application able to generate PSD2 compliant
test certificates with all possible PSD2 roles (ASPSP, PISP, AISP, PIISP).

## Prerequisites

- Java 17 or higher
- Json file containing tpp information.
example: `Tpp.json`
```json
{
    "authorizationNumber": "PSDDE-FAKENCA-87B2AC",
    "roles": [
        "PISP", "AISP"
    ],
    "organizationName": "Fictional Corporation AG",
    "organizationUnit": "Information Technology",
    "domainComponent": "public.corporation.de",
    "localityName": "Nuremberg",
    "stateOrProvinceName": "Bayern",
    "countryCode": "DE",
    "validity": 365,
    "commonName": "Fake NCA",
    "ocspCheckNeeded": false
} 
```

### How to use and run a library in other project

#### 1- Create a New Maven Project:
Create a new Maven project using a similar command

```shell
mvn archetype:generate -DgroupId=com.example -DartifactId=my-app -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false
```

#### 2- Add the Library as a Dependency:
Open the `pom.xml` file of the new project and add a dependency for your library:

```xml
<dependencies>
    <dependency>
        <groupId>de.adorsys.psd2.qwac</groupId>
        <artifactId>certificate-generator-lib</artifactId>
        <version>4.2</version>
    </dependency>
</dependencies>
```

#### 3- Use the Library in Your Code:
You can now use the library classes and methods in your project. For example:

```java
package com.example;

public class App {
    private static final Logger logger = LoggerFactory.getLogger(CertificateService.class);
    public static void main(String[] args) {
        final int ARGS_SIZE = 1;
        try {
            // Check if the required arguments are provided
            if (args.length < ARGS_SIZE) {
                log.info("Usage: java App <path/to/yourTppFile.json> [--target_folder <target_folder>]");
                return;
            }

            String tppJsonFilePath = args[0];
            // Optional target folder argument
            String targetFolder = args.length > 1 && "--target_folder".equals(args[1]) ? args[2] : "certs";

            CertificateService certificateService = new CertificateService();

            certificateService.generatePemFilesCerts(tppJsonFilePath, targetFolder);
        } catch (IOException e) {
             logger.error("An error occurred: {}", e.getMessage(), e);
        }
    }
}
```

#### 4- Build and Run Your Application:
Navigate to your project directory and build the application:

```shell
mvn clean package
```

##### Then run the application:
Using a default target folder:

```shell
java -cp target/my-app-1.0-SNAPSHOT.jar com.example.App <path/to/yourTppFile.json>
```

Specifying the target folder:

```shell
java -cp target/my-app-1.0-SNAPSHOT.jar com.example.App <path/to/yourTppFile.json> --target_folder <path/to/target_folder>
```

