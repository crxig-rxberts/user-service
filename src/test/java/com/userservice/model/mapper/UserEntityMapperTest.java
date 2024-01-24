package com.userservice.model.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

import com.userservice.model.entity.UserEntity;
import com.userservice.model.entity.UserRole;
import com.userservice.model.entity.mapper.UserEntityMapper;
import com.userservice.model.request.RegistrationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@ExtendWith(MockitoExtension.class)
class UserEntityMapperTest {

    @Mock
    private RegistrationRequest request;
    @Mock
    private BCryptPasswordEncoder passwordEncoder;

    @InjectMocks
    private UserEntityMapper mapper;


    @Test
    void userEntityMapperTest() {
        mockValidRegistrationRequest();

        UserEntity userEntity = mapper.map(request);

        assertEquals("userId", userEntity.getUserId());
        assertEquals("John", userEntity.getFirstName());
        assertEquals("Doe", userEntity.getLastName());
        assertEquals("john.doe@example.com", userEntity.getEmail());
        assertEquals("encodedPassword", userEntity.getPassword());
        assertEquals(UserRole.USER, userEntity.getUserRole());
    }

    private void mockValidRegistrationRequest() {
        when(request.getUserId()).thenReturn("userId");
        when(request.getFirstName()).thenReturn("John");
        when(request.getLastName()).thenReturn("Doe");
        when(request.getEmail()).thenReturn("john.doe@example.com");
        when(request.getPassword()).thenReturn("password123");
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
    }
}
