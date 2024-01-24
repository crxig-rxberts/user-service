package com.userservice.exception;

import lombok.Getter;

@Getter
public class NotFoundException extends ServiceException {

    public NotFoundException(String msg) {
        super(msg);
    }
}
