package com.sensor.authservice.service;

import com.sensor.authservice.dto.AuthResponse;
import com.sensor.authservice.dto.LoginRequest;
import com.sensor.authservice.dto.SignUpRequest;
import com.sensor.authservice.entity.User;
import com.sensor.authservice.repository.UserRepository;
import com.sensor.authservice.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;

    @Transactional
    public AuthResponse signup(SignUpRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setName(request.getName());

        userRepository.save(user);

        String token = tokenProvider.generateToken(user.getEmail());
        return new AuthResponse(token, user.getEmail(), user.getName());
    }

    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        String token = tokenProvider.generateToken(user.getEmail());
        return new AuthResponse(token, user.getEmail(), user.getName());
    }
}
