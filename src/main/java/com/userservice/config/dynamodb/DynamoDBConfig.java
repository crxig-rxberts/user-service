package com.userservice.config.dynamodb;

import com.amazonaws.auth.*;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.datamodeling.*;
import com.amazonaws.services.dynamodbv2.model.*;
import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.entity.UserEntity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.util.StringUtils;

import static java.util.Optional.ofNullable;

@Configuration
@Slf4j
public class DynamoDBConfig {

    @Value("${dynamodb.table.envPostfix:}")
    private String dynamoTableEnvPostfix;

    @Value("${aws.profile:notconfigured}")
    private String awsProfile;

    @Value("${aws.credentialsprovider:env}")
    private String credentialsProvider;

    @Value("${aws.dynamodb.endpoint:}")
    private String amazonDynamoDBEndpoint;

    @Value("${aws.region:eu-west-1}")
    private String amazonAWSRegion;

    @Bean
    public DynamoDBMapperConfig dynamoDBMapperConfig() {
        return new DynamoDBMapperConfig.Builder()
                .withTableNameResolver((clazz, config) -> {
                    DynamoDBTable dynamoDBTable = clazz.getDeclaredAnnotation(DynamoDBTable.class);
                    if (dynamoDBTable == null) {
                        throw new IllegalStateException(clazz + " not annotated with @DynamoDBTable");
                    }
                    return dynamoDBTable.tableName() + dynamoTableEnvPostfix;
                })
                .build();
    }

    @Bean
    @Profile({"!local & !test & !integration"})
    public AmazonDynamoDB amazonDynamoDB() {
        AmazonDynamoDBClientBuilder builder = AmazonDynamoDBClientBuilder.standard()
                .withCredentials(getCredentialProvider())
                .withRegion(Regions.fromName(amazonAWSRegion));

        if (StringUtils.hasText(amazonDynamoDBEndpoint)) {
            builder.setEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(amazonDynamoDBEndpoint, amazonAWSRegion));
        }

        return builder.build();
    }

    @Bean
    @Profile({"local", "test", "integration"})
    public AmazonDynamoDB amazonDynamoDBLocal() {
        return AmazonDynamoDBClientBuilder.standard()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(amazonDynamoDBEndpoint, "local"))
                .withCredentials(new AWSStaticCredentialsProvider(new BasicAWSCredentials("dummy", "dummy")))
                .build();
    }

    private AWSCredentialsProvider getCredentialProvider() {
        if ("profile".equals(credentialsProvider)) {
            return new ProfileCredentialsProvider(awsProfile);
        }
        return new EnvironmentVariableCredentialsProvider();
    }

    @Bean
    public DynamoDBMapper dynamoDBMapper(AmazonDynamoDB amazonDynamoDB, DynamoDBMapperConfig config) {
        DynamoDBMapper mapper = new DynamoDBMapper(amazonDynamoDB, config);
        createTableIfNotExists(amazonDynamoDB, mapper, UserEntity.class);
        createTableIfNotExists(amazonDynamoDB, mapper, ConfirmationTokenEntity.class);
        return mapper;
    }

    private <T> void createTableIfNotExists(AmazonDynamoDB amazonDynamoDB, DynamoDBMapper mapper, Class<T> entityClass) {
        CreateTableRequest ctr = mapper.generateCreateTableRequest(entityClass);
        ProvisionedThroughput commonThroughput = new ProvisionedThroughput(5L, 5L);
        ctr.setProvisionedThroughput(commonThroughput);

        // Check for Global Secondary Index and set their throughput and projection type if one exists.
        ofNullable(ctr.getGlobalSecondaryIndexes())
                .ifPresent(gsis -> gsis.forEach(gsi -> {
                    gsi.setProvisionedThroughput(commonThroughput);
                    gsi.setProjection(new Projection().withProjectionType(ProjectionType.ALL));
                }));

        try {
            amazonDynamoDB.describeTable(ctr.getTableName());
            log.info("Table " + ctr.getTableName() + " already exists");
        } catch (ResourceNotFoundException e) {
            amazonDynamoDB.createTable(ctr);
            log.info("Created DynamoDB table: " + ctr.getTableName());
        }
    }
}
