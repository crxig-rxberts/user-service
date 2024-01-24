package com.userservice.service;

import com.userservice.exception.NotFoundException;
import com.userservice.exception.UnauthorizedException;
import com.userservice.repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
@Slf4j
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private static final String NOT_FOUND_MSG = "No user for userId: %s";

    private void authenticateGivenPassword(String userId, String givenPassword) {
        var user = userRepository.read(userId)
                .orElseThrow(() -> new NotFoundException(String.format(NOT_FOUND_MSG, userId)));

        if (!bCryptPasswordEncoder.matches(givenPassword, user.getPassword())) {
            throw new UnauthorizedException("Given Password incorrect for User.");
        }
    }

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        try {
            return userRepository.read(userId)
                    .orElseThrow(() -> new NotFoundException(String.format(NOT_FOUND_MSG, userId)));
        } catch (NotFoundException e) {
            throw new UsernameNotFoundException(String.format(NOT_FOUND_MSG, userId));
        }
    }
}
