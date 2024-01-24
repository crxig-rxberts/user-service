package com.userservice.model.entity;

import com.amazonaws.services.dynamodbv2.datamodeling.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@Data
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@DynamoDBTable(tableName = "user-accounts")
public class UserEntity implements UserDetails {

    @DynamoDBHashKey
    private String userId;

    @DynamoDBAttribute
    private String firstName;

    @DynamoDBAttribute
    private String lastName;

    @DynamoDBAttribute
    private String email;

    @DynamoDBAttribute
    private String password;

    @DynamoDBTypeConvertedEnum
    private UserRole userRole;

    @DynamoDBAttribute
    private Boolean locked = false;

    @DynamoDBAttribute
    private Boolean enabled = false;

    @Override
    @DynamoDBIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority(userRole.name()));
    }

    @Override
    @DynamoDBIgnore
    public String getUsername() {
        return userId;
    }

    @Override
    @DynamoDBIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @DynamoDBIgnore
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    @DynamoDBIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @DynamoDBIgnore
    public boolean isEnabled() {
        return enabled;
    }
}
