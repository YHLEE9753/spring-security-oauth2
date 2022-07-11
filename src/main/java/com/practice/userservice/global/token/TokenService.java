package com.practice.userservice.global.token;

import com.practice.userservice.global.OAuthYamlRead;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Base64;
import java.util.Date;
import javax.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class TokenService {
    private final OAuthYamlRead oAuthYamlRead;
    private String secretKey;
    private final long tokenPeriod;
    private final long refreshPeriod;

    public TokenService(OAuthYamlRead oAuthYamlRead) {
        this.oAuthYamlRead = oAuthYamlRead;
        this.secretKey = oAuthYamlRead.getTokenSecret();
        this.tokenPeriod = oAuthYamlRead.getTokenExpiry();
        this.refreshPeriod = oAuthYamlRead.getRefreshTokenExpiry();
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // 토큰 생성
    public Token generateToken(String uid, String role) {

        // Claims 에 권한 설정(uid : email(식별자))
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("role", role);

        Date now = new Date();
        // AccessToken, RefreshToken 를 Token 에 담아 반환한다.
        return new Token(
            Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + tokenPeriod))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact(),
            Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + refreshPeriod))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact());
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
        return refreshPeriod;
    }
}
