package com.userservice.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.userservice.model.request.RegistrationRequest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@AutoConfigureMockMvc
public class ServiceTestClient {

    private final MockMvc mockMvc;
    private final ObjectMapper objectMapper;

    public ServiceTestClient(MockMvc mockMvc, ObjectMapper objectMapper) {
        this.mockMvc = mockMvc;
        this.objectMapper = objectMapper;
    }

    public ResultActions sendRegistrationRequest(RegistrationRequest request) throws Exception {
        return mockMvc.perform(post("/api/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));
    }
}
