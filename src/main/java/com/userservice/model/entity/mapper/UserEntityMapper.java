package com.userservice.model.entity.mapper;

import com.userservice.model.entity.UserEntity;
import com.userservice.model.entity.UserRole;
import com.userservice.model.request.RegistrationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class UserEntityMapper {

    private final BCryptPasswordEncoder passwordEncoder;

    public UserEntity map(RegistrationRequest request) {
        return UserEntity.builder()
                .userId(request.getUserId())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .userRole(UserRole.USER)
                .build();
    }
}
