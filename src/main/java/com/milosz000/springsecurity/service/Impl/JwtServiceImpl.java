package com.milosz000.springsecurity.service.Impl;

import com.milosz000.springsecurity.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;

@Service
public class JwtServiceImpl implements JwtService {

    // use a value from .env
    @Value("${JWT_SECRET}")
    private String SECRET_KEY;

    @Override
    public String getUsername(String token) {
        return null;
    }

    // JWTs claims are pieces of information asserted about a subject. In a JWT, a claim appears as a name/value pair.
    private Claims extractAllClaims(String token) {
        // I have to return all the claims from jwt
        return Jwts.parserBuilder()
                // I have to set signing key
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();



    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
