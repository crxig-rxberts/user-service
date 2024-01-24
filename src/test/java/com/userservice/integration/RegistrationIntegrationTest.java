package com.userservice.integration;

import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.entity.UserEntity;
import com.userservice.model.request.RegistrationRequest;
import com.userservice.repository.ConfirmationTokenRepository;
import com.userservice.repository.UserRepository;
import com.userservice.util.ServiceTestClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("integration")
class RegistrationIntegrationTest {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private ServiceTestClient serviceTestClient;

    private static final String TEST_USER_ID = "newUser";
    private static final String TEST_EMAIL = "jdoe@test.com";

    @AfterEach
    void tearDown() {
        userRepository.read(TEST_USER_ID).ifPresent(user -> userRepository.delete(TEST_USER_ID));

        var tokens = confirmationTokenRepository.readByUserId(TEST_USER_ID);
        if (!tokens.isEmpty()) {
            tokens.forEach(confirmationTokenRepository::delete);
        }
    }

    @Test
    void registerUserIntegrationTest() throws Exception {
        RegistrationRequest request = new RegistrationRequest(TEST_USER_ID, "John", "Doe", "P$ssWord123", TEST_EMAIL);

        serviceTestClient.sendRegistrationRequest(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("SUCCESS")));

        var userEntity = userRepository.read(TEST_USER_ID);
        assertTrue(userEntity.isPresent());
        assertUserEntity(userEntity.get(), request);

        var tokenEntity = confirmationTokenRepository.readByUserId(TEST_USER_ID);
        assertNotNull(tokenEntity);
        assertTokenEntity(tokenEntity.get(0), userEntity.get());

        // verify email notification sent
    }

    private void assertUserEntity(UserEntity userEntity, RegistrationRequest request) {
        assertEquals(request.getUserId(), userEntity.getUserId());
        assertEquals(request.getFirstName(), userEntity.getFirstName());
        assertEquals(request.getLastName(), userEntity.getLastName());
        assertEquals(request.getEmail(), userEntity.getEmail());
        // Additional assertions like checking if the password is hashed
    }

    private void assertTokenEntity(ConfirmationTokenEntity tokenEntity, UserEntity userEntity) {
        assertNotNull(tokenEntity.getToken());
        assertEquals(userEntity.getUserId(), tokenEntity.getUserId());
        assertNotNull(tokenEntity.getCreatedAt());
        assertNotNull(tokenEntity.getExpiresAt());
        // Additional assertions like confirming the token expiry time
    }


}
