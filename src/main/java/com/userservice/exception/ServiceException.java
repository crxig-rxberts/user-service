package com.userservice.exception;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Getter
@Slf4j
public class ServiceException extends RuntimeException {

    private final String logMsg;
    
    public ServiceException(String logMsg) {
        this.logMsg = logMsg;
    }
}