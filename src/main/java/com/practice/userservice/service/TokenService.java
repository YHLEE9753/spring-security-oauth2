package com.practice.userservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {
    // 추가 리펙토링 필요
    private String secretKey = "tokensecretkeydoublecaseqwdqwdqwdqwdqwdqwdwqdqwdq";
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    Key key = Keys.hmacShaKeyFor(keyBytes);

    @PostConstruct // 의존성 주입 후 초기화(Key 생성)
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // 토큰 생성
    public Token generateToken(String uid, String role) {
        // AccessToken 만료기간 : 10분
        long tokenPeriod = 1000L * 60L * 10L;
        // RefreshToken 만료기간 : 3주
        long refreshPeriod = 1000L * 60L * 60L * 24L * 30L * 3L;

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
                .signWith(key)
                .compact(),

            Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + refreshPeriod))
                .signWith(key)
                .compact());
    }

    public boolean verifyToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token);
            return claims.getBody()
                .getExpiration()
                .after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String getUid(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(getSignKey())
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    private Key getSignKey(){
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }
}
