package com.userservice.util;

import ch.qos.logback.core.AppenderBase;
import ch.qos.logback.classic.spi.ILoggingEvent;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class ListAppender extends AppenderBase<ILoggingEvent> {
    private final List<ILoggingEvent> logs = new ArrayList<>();

    @Override
    protected void append(ILoggingEvent event) {
        logs.add(event);
    }

}