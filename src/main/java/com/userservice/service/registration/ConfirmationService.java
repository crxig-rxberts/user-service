package com.userservice.service.registration;

import com.userservice.exception.NotFoundException;
import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.response.BaseResponse;
import com.userservice.model.response.ErrorResponse;
import com.userservice.model.response.ResponseStatus;
import com.userservice.repository.ConfirmationTokenRepository;
import com.userservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import static java.util.Optional.of;

@Slf4j
@Service
@RequiredArgsConstructor
public class ConfirmationService {

    private static final String NOT_FOUND_ERROR_MESSAGE = "ConfirmationToken does not exist.";
    private static final String ALREADY_CONFIRMED_MESSAGE = "ConfirmationToken already confirmed.";
    private static final String EXPIRED_ERROR_MESSAGE = "ConfirmationToken Expired, User Deleted from DB, re-registration required";

    private final UserRepository userRepository;
    private final ConfirmationTokenRepository confirmationTokenRepository;

    public ResponseEntity<BaseResponse> confirmToken(String token) throws SecurityException {
        var tokenEntity = confirmationTokenRepository.read(token)
                .orElseThrow(() -> new NotFoundException(NOT_FOUND_ERROR_MESSAGE));

        return of(tokenEntity)
                .filter(this::notConfirmed)
                .filter(this::notExpired)
                .map(this::activateUserAccount)
                .orElseGet(() -> prepareInvalidTokenResponse(tokenEntity));
    }

    private boolean notConfirmed(ConfirmationTokenEntity tokenEntity) {
        return tokenEntity.getConfirmedAt() == null;
    }

    private boolean notExpired(ConfirmationTokenEntity tokenEntity) {
        return !tokenEntity.getExpiresAt().isBefore(LocalDateTime.now());
    }

    private ResponseEntity<BaseResponse> prepareInvalidTokenResponse(ConfirmationTokenEntity tokenEntity) {
        if (tokenEntity.getConfirmedAt() != null) {
            return tokenAlreadyConfirmedResponse();
        } else {
            return expiredTokenResponse(tokenEntity);
        }
    }

    private ResponseEntity<BaseResponse> tokenAlreadyConfirmedResponse() {
        return ResponseEntity.ok(new ErrorResponse(ResponseStatus.SUCCESS, ALREADY_CONFIRMED_MESSAGE));
    }

    private ResponseEntity<BaseResponse> expiredTokenResponse(ConfirmationTokenEntity tokenEntity) {
        userRepository.delete(tokenEntity.getUserId());
        return ResponseEntity.ok(new ErrorResponse(ResponseStatus.FAILURE, EXPIRED_ERROR_MESSAGE));
    }

    private ResponseEntity<BaseResponse> activateUserAccount(ConfirmationTokenEntity tokenEntity) {
        tokenEntity.setConfirmedAt(LocalDateTime.now());
        confirmationTokenRepository.delete(tokenEntity);

        userRepository.read(tokenEntity.getUserId()).ifPresent(
                userEntity -> userEntity.setEnabled(true)
        );

        log.info("User account enabled. Token Entity deleted from DB.");
        return ResponseEntity.ok(new BaseResponse(ResponseStatus.SUCCESS));
    }
}
