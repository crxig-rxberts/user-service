package com.userservice.model.response;

import com.userservice.model.entity.UserEntity;

public class UserResponse extends BaseResponse {

    private UserEntity userEntity;

    public UserResponse(ResponseStatus responseStatus) {
        super(responseStatus);
    }
}