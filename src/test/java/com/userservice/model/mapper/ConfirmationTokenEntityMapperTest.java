package com.userservice.model.mapper;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.entity.UserEntity;
import com.userservice.model.entity.mapper.ConfirmationTokenEntityMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.LocalDateTime;

class ConfirmationTokenEntityMapperTest {

    private final ConfirmationTokenEntityMapper mapper = new ConfirmationTokenEntityMapper();

    @Test
    void confirmationTokenEntityMapperTest() {
        UserEntity userEntity = Mockito.mock(UserEntity.class);
        Mockito.when(userEntity.getUserId()).thenReturn("someUserId");

        ConfirmationTokenEntity tokenEntity = mapper.map(userEntity);

        assertNotNull(tokenEntity.getToken());
        assertTrue(tokenEntity.getCreatedAt().isBefore(LocalDateTime.now().plusMinutes(1)));
        assertTrue(tokenEntity.getExpiresAt().isAfter(LocalDateTime.now()));
        assertEquals("someUserId", tokenEntity.getUserId());
    }
}
