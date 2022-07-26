package com.practice.userservice.global.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Base64;
import java.util.Date;
import org.springframework.stereotype.Component;

@Component
public class TokenGenerator {

    private final String issuer;
    private String secretKey;
    private final long tokenPeriod;
    private final long refreshPeriod;

    public TokenGenerator(JwtProperties jwtProperties) {
        this.issuer = jwtProperties.getIssuer();
        this.secretKey = jwtProperties.getTokenSecret();
        this.tokenPeriod = jwtProperties.getTokenExpiry();
        this.refreshPeriod = jwtProperties.getRefreshTokenExpiry();
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public Tokens generateTokens(String uid, String role) {
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("role", role);
        Date now = new Date();

        return new Tokens(
            generateAccessToken(claims, now),
            generateRefreshToken(claims, now)
        );
    }

    public String generateAccessToken(Claims claims, Date now) {
        return Jwts.builder()
            .setIssuer(issuer)
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + tokenPeriod))
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    }

    public String generateAccessToken(String uid, String[] role) {
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("role", role);
        Date now = new Date();

        return this.generateAccessToken(claims, now);
    }

    public String generateRefreshToken(Claims claims, Date now) {
        return Jwts.builder()
            .setIssuer(issuer)
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(new Date(now.getTime() + refreshPeriod))
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    }

}
