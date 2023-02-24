package com.milosz000.springsecurity.config;

import com.milosz000.springsecurity.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
/* Spring guarantees that the OncePerRequestFilter is executed only once for a given request. This excludes scenario,
where different servlets will call the same filter */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // first of all I have to check if JwtToken exists

        /* I have to try extract a header from the request
         Content of header -> Authorization: Bearer <token> */
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // check if jwtToken exists and if it's correct
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            /* if the JwtToken doesn't exist I have to go to the next filter
             filterChain.doFilter() methods is proceeding to the next element in the chain  */
            filterChain.doFilter(request,response);
            return;
        }

        // I have to extract the JwtToken, so I have to exclude the word "Bearer"
        jwt = authHeader.substring(7);
        userEmail = jwtService.getUsername(jwt); // todo: extract userEmail from JWT token

    }
}
