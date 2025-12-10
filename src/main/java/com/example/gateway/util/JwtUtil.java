
package com.example.gateway.util;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${app.jwtSecret}")
    private String jwtSecret;

    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new MACVerifier(jwtSecret.getBytes(StandardCharsets.UTF_8));
            
            if (!signedJWT.verify(verifier)) {
                return false;
            }

            Date expiryTime = signedJWT.getJWTClaimsSet().getExpirationTime();
            return expiryTime != null && expiryTime.after(new Date());

        } catch (Exception e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract username", e);
        }
    }

    public Integer extractUserId(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            Object userIdObj = signedJWT.getJWTClaimsSet().getClaim("id");
            
            if (userIdObj instanceof Number) {
                return ((Number) userIdObj).intValue();
            } else if (userIdObj instanceof String) {
                return Integer.valueOf((String) userIdObj);
            }
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract user ID", e);
        }
    }
}