package com.practice.userservice.global.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.util.Base64;
import java.util.Date;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    private String secretKey;
    private final long refreshTokenPeriod;
    private final long accessTokenPeriod;

    public TokenService(JwtYamlRead jwtYamlRead) {
        this.secretKey = jwtYamlRead.getTokenSecret();
        this.refreshTokenPeriod = jwtYamlRead.getRefreshTokenExpiry();
        this.accessTokenPeriod = jwtYamlRead.getTokenExpiry();
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public boolean verifyToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token);

            return claims.getBody()
                .getExpiration()
                .after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String [] getRole(String token) {
        return new String [] {
            (String) Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody()
                .get("role")
        };
    }

    public String getUid(String token) {
        return Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public String changeToToken(String header) {
        return header.substring("Bearer ".length());
    }

    public long getRefreshPeriod() {
        return refreshTokenPeriod;
    }
    public long getAccessTokenPeriod() {
        return accessTokenPeriod;
    }
}
