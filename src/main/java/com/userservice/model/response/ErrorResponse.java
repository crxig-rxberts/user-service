package com.userservice.model.response;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;

@Data
@EqualsAndHashCode(callSuper = true)
@SuperBuilder
public class ErrorResponse extends BaseResponse {

    private String message;

    public ErrorResponse(ResponseStatus status, String message) {
        super(status);
        this.message = message;
    }
}
