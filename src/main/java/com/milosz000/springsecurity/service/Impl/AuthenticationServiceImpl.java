package com.milosz000.springsecurity.service.Impl;

import com.milosz000.springsecurity.config.JwtService;
import com.milosz000.springsecurity.dto.AuthenticationRequestDto;
import com.milosz000.springsecurity.dto.AuthenticationResponseDto;
import com.milosz000.springsecurity.dto.RegisterRequestDto;
import com.milosz000.springsecurity.entity.User;
import com.milosz000.springsecurity.entity.enums.Role;
import com.milosz000.springsecurity.repository.UserRepository;
import com.milosz000.springsecurity.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponseDto register(RegisterRequestDto request) {
        // save user into database
        User user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(user);

        //generate jwtToken
        String token = jwtService.generateToken(user);
        return AuthenticationResponseDto.builder()
                .token(token)
                .build();
    }

    @Override
    public AuthenticationResponseDto authenticate(AuthenticationRequestDto request) {
        // authenticate user using authenticationManager
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );
        // if user not exists then throw exception
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(
                () -> new UsernameNotFoundException("User not found"));

        String token = jwtService.generateToken(user);

        return AuthenticationResponseDto.builder()
                .token(token)
                .build();
    }
}
