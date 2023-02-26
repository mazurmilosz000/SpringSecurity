package com.milosz000.springsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // JWT expiration time
    private static final int JWT_VALIDITY = 5 * 60 * 60;



    // TODO: fix env variables
    // use a value from .env
   //  @Value("${JWT_SECRET}")
    // private final String SECRET_KEY = System.getProperty("JWT_SECRET");
    private final String SECRET_KEY = "F31ADD382EF16309DA681CA917E4E03B95E084D4E2DB57DE10A5D971D9C4A712";




    public String getUsername(String token) {
        /* I am calling the extractClaim() method
         :: its called method reference and in my case it refers to method getSubject() from Claims class */
        return extractClaim(token, Claims::getSubject);

    }


    /* JWTs claims are pieces of information asserted about a subject. In a JWT, a claim appears as a name/value pair.

     method to extract one claim
     Function<Claims, T> - <Claims> - type of the input to the function, <T> - type of the output */
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
            final Claims claims = extractAllClaims(token);
            return claimsResolver.apply(claims);
    }

    // method to generate token without extra claims
    public String generateToken(
            UserDetails userDetails
    ) {
        // I return generateToken method but, as a extraClaims map, I use an empty HashMap
        return generateToken(new HashMap<>(), userDetails);
    }


    // method to generate token with extra claims
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts.builder()
                // as claims I set my extraClaims
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                // set when token is created
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * JWT_VALIDITY))
                // set private key and signature algorithm
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                // method that generate and return token
                .compact();
    }

    private boolean isTokenExpired(String token) {
        Date expirationDate = extractExpirationDate(token);

        // I have t check if expiration date is before current date
        return (expirationDate.before(new Date(System.currentTimeMillis())));
    }

    private Date extractExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // method to validate the token
    public boolean validateToken(String token, UserDetails userDetails) {
        /* I take the username from the token, and then validate it with the username from userDetails and check if the
        token is not expired */
        String usernameFromToken = getUsername(token);
        return (usernameFromToken.equals(userDetails.getUsername()) && !isTokenExpired(token));


    }

    /* method to extract all claims
     for retrieving any information from token I will need the secret key */

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
