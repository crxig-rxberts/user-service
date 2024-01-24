package com.userservice.repository;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapper;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBQueryExpression;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.userservice.model.entity.ConfirmationTokenEntity;
import org.springframework.stereotype.Repository;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static java.util.Optional.ofNullable;

@Repository
public class ConfirmationTokenRepository {

    private final DynamoDBMapper dynamoDBMapper;

    public ConfirmationTokenRepository(DynamoDBMapper dynamoDBMapper) {
        this.dynamoDBMapper = dynamoDBMapper;
    }

    public ConfirmationTokenEntity save(ConfirmationTokenEntity confirmationTokenEntity) {
        dynamoDBMapper.save(confirmationTokenEntity);
        return confirmationTokenEntity;
    }

    public Optional<ConfirmationTokenEntity> read(String token) {
        var tokenEntity = dynamoDBMapper.load(ConfirmationTokenEntity.class, token);
        return ofNullable(tokenEntity);
    }

    public List<ConfirmationTokenEntity> readByUserId(String userId) {
        DynamoDBQueryExpression<ConfirmationTokenEntity> queryExpression = new DynamoDBQueryExpression<ConfirmationTokenEntity>()
                .withIndexName("UserIdIndex")
                .withConsistentRead(false)
                .withKeyConditionExpression("userId = :userIdVal")
                .withExpressionAttributeValues(Collections.singletonMap(":userIdVal", new AttributeValue().withS(userId)));

        return dynamoDBMapper.query(ConfirmationTokenEntity.class, queryExpression);
    }

    public void delete(ConfirmationTokenEntity confirmationTokenEntity) {
        dynamoDBMapper.delete(confirmationTokenEntity);
    }
}
