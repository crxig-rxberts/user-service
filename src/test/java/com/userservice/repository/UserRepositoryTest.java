package com.userservice.repository;

import com.userservice.exception.ConflictException;
import com.userservice.model.entity.UserEntity;
import com.userservice.model.entity.UserRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    private static final UserEntity TEST_USER = UserEntity.builder()
                .userId("testUserId")
                .firstName("Test")
                .lastName("User")
                .email("test@example.com")
                .password("password")
                .userRole(UserRole.USER)
                .enabled(true)
                .locked(false)
                .build();


    @AfterEach
    void tearDown() {
        userRepository.delete(TEST_USER.getUserId());
    }

    @Test
    void saveAndReadUser() {
        var savedUser = userRepository.save(TEST_USER);
        assertNotNull(savedUser);

        var readUser = userRepository.read(savedUser.getUserId());
        assertTrue(readUser.isPresent());
        assertEquals("Test", readUser.get().getFirstName());
        assertEquals("User", readUser.get().getLastName());
        assertEquals("test@example.com", readUser.get().getEmail());
        assertEquals("password", readUser.get().getPassword());
        assertEquals(UserRole.USER, readUser.get().getUserRole());
        assertTrue(readUser.get().isEnabled());
        assertTrue(readUser.get().isAccountNonLocked());
    }

    @Test
    void deleteUser() {
        userRepository.save(TEST_USER);

        userRepository.delete(TEST_USER.getUserId());

        var readUser = userRepository.read(TEST_USER.getUserId());
        assertFalse(readUser.isPresent());
    }

    @Test
    void checkForExistingRecord_ThrowsConflictException() {
        userRepository.save(TEST_USER);

        assertThrows(ConflictException.class, () ->
                userRepository.checkForExistingRecord(TEST_USER.getUserId()));
    }
}
