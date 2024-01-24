package com.userservice.exception;

import lombok.Getter;

@Getter
public class ConflictException extends ServiceException {

    public ConflictException(String msg) {
        super(msg);
    }
}
