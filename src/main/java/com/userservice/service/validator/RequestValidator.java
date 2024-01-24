package com.userservice.service.validator;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.Validation;
import javax.validation.Validator;
import java.util.Set;

public class RequestValidator {
    protected static final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    private RequestValidator() {
    }

    public static <T> void validateRequest(T request) throws ConstraintViolationException {
        Set<ConstraintViolation<T>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            throw new ConstraintViolationException(violations);
        }
    }
}