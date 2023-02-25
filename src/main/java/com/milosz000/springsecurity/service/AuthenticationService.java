package com.milosz000.springsecurity.service;

import com.milosz000.springsecurity.dto.AuthenticationRequestDto;
import com.milosz000.springsecurity.dto.AuthenticationResponseDto;
import com.milosz000.springsecurity.dto.RegisterRequestDto;

public interface AuthenticationService {
   AuthenticationResponseDto register(RegisterRequestDto request);

    AuthenticationResponseDto authenticate(AuthenticationRequestDto request);
}
