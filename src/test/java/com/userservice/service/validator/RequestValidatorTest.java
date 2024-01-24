package com.userservice.service.validator;

import com.userservice.model.request.RegistrationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.validation.ConstraintViolationException;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class RequestValidatorTest {

        @Test
        void validateUserRequest_when_inputIsValid_then_expectNoException() {
            RegistrationRequest request = RegistrationRequest.builder()
                    .userId("displayName")
                    .firstName("John")
                    .lastName("Doe")
                    .email("johndoe@example.com")
                    .password("Password123@")
                    .build();

            assertDoesNotThrow(() -> RequestValidator.validateRequest(request));
        }

        @Test
        void validateUserRequest_when_inputIsInvalid_then_expectConstraintViolationException() {
            RegistrationRequest request = RegistrationRequest.builder()
                    .userId("")
                    .firstName("")
                    .lastName("")
                    .email("not_an_email_address")
                    .password("invalid")
                    .build();

            ConstraintViolationException exception =
                    assertThrows(ConstraintViolationException.class, () -> RequestValidator.validateRequest(request));
            assertEquals(5, exception.getConstraintViolations().size());
        }
}
