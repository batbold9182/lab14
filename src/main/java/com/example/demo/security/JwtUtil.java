package com.example.demo.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    private static final String SECRET_KEY = "your-very-secure-secret-key-your-very-secure-secret-key"; // Must be 32+ chars
    private static final long EXPIRATION_TIME = 1000 * 60 * 60; // 1 hour

    private SecretKey getSigningKey() {  // ✅ FIXED: Use SecretKey
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String username) {
        return Jwts.builder()
            .subject(username)  // ✅ FIXED
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .signWith(getSigningKey(), Jwts.SIG.HS256)  // ✅ FIXED
            .compact();
    }

    public String extractUsername(String token) {
        return Jwts.parser()  // ✅ FIXED: Use `parser()` instead of `parserBuilder()`
            .verifyWith(getSigningKey())  // ✅ FIXED: `verifyWith()` is required in JJWT 0.12.x
            .build()
            .parseSignedClaims(token)
            .getPayload()
            .getSubject();
    }

    public boolean validateToken(String token, String username) {
        String extractedUsername = extractUsername(token);
        return extractedUsername.equals(username) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())  // ✅ FIXED: Use `verifyWith()`
            .build()
            .parseSignedClaims(token)
            .getPayload()
            .getExpiration();
    }
}
