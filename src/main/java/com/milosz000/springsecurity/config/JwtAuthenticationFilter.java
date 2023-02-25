package com.milosz000.springsecurity.config;

import com.milosz000.springsecurity.service.UserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
/* Spring guarantees that the OncePerRequestFilter is executed only once for a given request. This excludes scenario,
where different servlets will call the same filter */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
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
        final String jwtToken;
        final String userEmail;

        // check if jwtToken exists and if it's correct
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            /* if the JwtToken doesn't exist I have to go to the next filter
             filterChain.doFilter() methods is proceeding to the next element in the chain  */
            filterChain.doFilter(request,response);
            return;
        }

        // I have to extract the JwtToken, so I have to exclude the word "Bearer"
        jwtToken = authHeader.substring(7);
        userEmail = jwtService.getUsername(jwtToken);

        /* check if userEmail is not null and if the user is already authenticated
         if getAuthentication == null -> user is not authenticated */
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if(jwtService.validateToken(jwtToken, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                // I dont have user credentials
                                null,
                                userDetails.getAuthorities()
                        );

                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }
        filterChain.doFilter(request, response);

    }
}
