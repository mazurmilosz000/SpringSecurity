package com.milosz000.springsecurity.controller;

import com.milosz000.springsecurity.dto.AuthenticationRequestDto;
import com.milosz000.springsecurity.dto.AuthenticationResponseDto;
import com.milosz000.springsecurity.dto.RegisterRequestDto;
import com.milosz000.springsecurity.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponseDto> register(
            @RequestBody RegisterRequestDto request) {

        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponseDto> register(
            @RequestBody AuthenticationRequestDto request) {

        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
