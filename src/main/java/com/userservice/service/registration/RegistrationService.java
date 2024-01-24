package com.userservice.service.registration;

import com.userservice.model.entity.ConfirmationTokenEntity;
import com.userservice.model.entity.UserEntity;
import com.userservice.model.entity.mapper.ConfirmationTokenEntityMapper;
import com.userservice.model.entity.mapper.UserEntityMapper;
import com.userservice.model.request.RegistrationRequest;
import com.userservice.model.response.BaseResponse;
import com.userservice.repository.ConfirmationTokenRepository;
import com.userservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import static com.userservice.model.response.ResponseStatus.SUCCESS;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegistrationService {
    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final UserRepository userRepository;
    private final UserEntityMapper userEntityMapper;
    private final ConfirmationTokenEntityMapper tokenEntityMapper;

    public ResponseEntity<BaseResponse> register(RegistrationRequest request) {
        UserEntity userEntity = createAndSaveUser(request);
        ConfirmationTokenEntity tokenEntity = createAndSaveConfirmationToken(userEntity);

        sendEmailNotification(userEntity, userEntity.getEmail(), tokenEntity.getToken());

        return ResponseEntity.ok(new BaseResponse(SUCCESS));
    }

    private UserEntity createAndSaveUser(RegistrationRequest request) {
        userRepository.checkForExistingRecord(request.getUserId());
        UserEntity userEntity = userEntityMapper.map(request);
        userRepository.save(userEntity);
        log.info("User successfully saved to DB.");
        return userEntity;
    }

    private ConfirmationTokenEntity createAndSaveConfirmationToken(UserEntity userEntity) {
        ConfirmationTokenEntity tokenEntity = tokenEntityMapper.map(userEntity);
        confirmationTokenRepository.save(tokenEntity);
        log.info("Confirmation token successfully saved to DB. Token: {}", tokenEntity.getToken());
        return tokenEntity;
    }

    private void sendEmailNotification(UserEntity user, String email, String token) {
        // TODO: Send event downstream
    }
}
