package com.userservice.model.entity.mapper;

import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.entity.UserEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.UUID;

@Component
public class ConfirmationTokenEntityMapper {

    public ConfirmationTokenEntity map(UserEntity user) {
        return ConfirmationTokenEntity.builder()
                .token(UUID.randomUUID().toString())
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(30))
                .userId(user.getUserId())
                .build();
    }
}
