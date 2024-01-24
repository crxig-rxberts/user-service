package com.userservice.exception;

import lombok.Getter;

@Getter
public class UnauthorizedException extends ServiceException {

    public UnauthorizedException(String msg) {
        super(msg);
    }
}