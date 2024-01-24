package com.userservice.config.dynamodb;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTypeConverter;

import java.time.LocalDateTime;

public class LocalDateTimeConverter implements DynamoDBTypeConverter<String, LocalDateTime> {

    @Override
    public String convert(LocalDateTime time) {
        return time.toString();
    }

    @Override
    public LocalDateTime unconvert(String stringValue) {
        return LocalDateTime.parse(stringValue);
    }
}
