package com.userservice.service;

import com.userservice.exception.ConflictException;
import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.entity.UserEntity;
import com.userservice.model.entity.mapper.ConfirmationTokenEntityMapper;
import com.userservice.model.entity.mapper.UserEntityMapper;
import com.userservice.model.request.RegistrationRequest;
import com.userservice.model.response.BaseResponse;
import com.userservice.repository.ConfirmationTokenRepository;
import com.userservice.repository.UserRepository;
import com.userservice.service.registration.RegistrationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Objects;

import static com.userservice.model.response.ResponseStatus.SUCCESS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegistrationServiceTest {

    @Mock
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private UserEntityMapper userEntityMapper;
    @Mock
    private ConfirmationTokenEntityMapper tokenEntityMapper;
    @Mock
    private UserEntity userEntity;
    @Mock
    private ConfirmationTokenEntity tokenEntity;
    @InjectMocks
    private RegistrationService registrationService;

    private static final RegistrationRequest VALID_REQUEST = new RegistrationRequest("userId", "firstName", "lastName", "P@ssw0rd", "email@example.com");

    @Test
    void validRequest_expectUserAndConfirmationTokenCreatedAndOkResponse() {
        when(userEntityMapper.map(VALID_REQUEST)).thenReturn(userEntity);
        when(tokenEntityMapper.map(userEntity)).thenReturn(tokenEntity);
        when(userEntity.getEmail()).thenReturn(VALID_REQUEST.getEmail());

        ResponseEntity<BaseResponse> response = registrationService.register(VALID_REQUEST);

        verify(userRepository, times(1)).save(any(UserEntity.class));
        verify(confirmationTokenRepository, times(1)).save(any(ConfirmationTokenEntity.class));

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(SUCCESS, Objects.requireNonNull(response.getBody()).getStatus());
    }

    @Test
    void validRequest_whenUserExists_expectConflictException() {
        doThrow(new ConflictException("User already exists."))
                .when(userRepository).checkForExistingRecord(VALID_REQUEST.getUserId());

        assertThrows(ConflictException.class, () -> registrationService.register(VALID_REQUEST));

        verify(userRepository, never()).save(any(UserEntity.class));
        verify(confirmationTokenRepository, never()).save(any(ConfirmationTokenEntity.class));
    }
}
