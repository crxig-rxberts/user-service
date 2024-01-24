package com.userservice.repository;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.userservice.exception.ConflictException;
import com.userservice.model.entity.UserEntity;
import org.springframework.stereotype.Repository;

import java.util.Optional;

import static java.util.Optional.ofNullable;

@Repository
public class UserRepository {

    private final DynamoDBMapper dynamoDBMapper;

    public UserRepository(DynamoDBMapper dynamoDBMapper) {
        this.dynamoDBMapper = dynamoDBMapper;
    }

    public UserEntity save(UserEntity userEntity) {
        dynamoDBMapper.save(userEntity);
        return userEntity;
    }

    public Optional<UserEntity> read(String userId) {
        var userEntity = dynamoDBMapper.load(UserEntity.class, userId);
        return ofNullable(userEntity);
    }

    public void delete(String userId) {
        read(userId).ifPresent(dynamoDBMapper::delete);
    }

    public void checkForExistingRecord(String userId) {
        if (dynamoDBMapper.load(UserEntity.class, userId) != null) {
            throw new ConflictException("User already exists.");
        }
    }
}
