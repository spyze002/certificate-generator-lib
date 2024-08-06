
package de.bran.psd2.qwac.certificate.generator.lib.exception;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;

public class GlobalExceptionHandler {

    private static final String MESSAGE = "message";
    private static final String CODE = "code";
    private static final String DATE_TIME = "dateTime";

    private final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);


    public Map<String, String> handleInvalidFormatException(InvalidFormatException e, Class<?> handlerMethod) {
        log.warn("Invalid format exception handled in service: {}, message: {}",
                 handlerMethod.getSimpleName(), e.getMessage());
        return getHandlerContent("Invalid initial data");
    }


    public Map<String, String> handleCertificateException(CertificateGeneratorException e, Class<?> handlerMethod) {
        log.warn("Invalid format exception handled in service: {}, message: {}",
                 handlerMethod.getSimpleName(), e.getMessage());
        return getHandlerContent(e.getMessage());
    }

    private Map<String, String> getHandlerContent(String message) {
        Map<String, String> error = new ConcurrentHashMap<>();
        error.put(CODE, "400");
        error.put(MESSAGE, message);
        error.put(DATE_TIME, LocalDateTime.now().toString());
        return error;
    }
}
