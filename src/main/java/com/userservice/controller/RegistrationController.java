package com.userservice.controller;

import com.userservice.model.request.RegistrationRequest;
import com.userservice.model.response.BaseResponse;
import com.userservice.service.registration.ConfirmationService;
import com.userservice.service.registration.RegistrationService;
import com.userservice.service.validator.RequestValidator;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "api/registration")
@AllArgsConstructor
@Slf4j
public class RegistrationController {

    private final RegistrationService registrationService;
    private final ConfirmationService confirmationService;

    @PostMapping
    public ResponseEntity<BaseResponse> register(@RequestBody RegistrationRequest request) {
        RequestValidator.validateRequest(request);
        return registrationService.register(request);
    }

    @GetMapping(path = "confirm")
    public ResponseEntity<BaseResponse> confirm(@RequestParam("token") String token) {
        return confirmationService.confirmToken(token);
    }
}
