package com.userservice.model.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.*;
import com.userservice.config.dynamodb.LocalDateTimeConverter;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@DynamoDBTable(tableName = "confirmation-tokens")
public class ConfirmationTokenEntity {

    @DynamoDBHashKey
    private String token;

    @DynamoDBTypeConverted(converter = LocalDateTimeConverter.class)
    @DynamoDBAttribute
    private LocalDateTime createdAt;

    @DynamoDBTypeConverted(converter = LocalDateTimeConverter.class)
    @DynamoDBAttribute
    private LocalDateTime expiresAt;

    @DynamoDBTypeConverted(converter = LocalDateTimeConverter.class)
    @DynamoDBAttribute
    private LocalDateTime confirmedAt;

    @DynamoDBIndexHashKey(globalSecondaryIndexName = "UserIdIndex")
    private String userId;
}
