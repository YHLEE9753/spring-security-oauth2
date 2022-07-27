package com.practice.userservice.global.token;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.global.util.CoderUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private String secretKey;
    private final long refreshTokenPeriod;
    private final long accessTokenPeriod;

    private byte[] keyBytes;
    private Key key;

    public TokenService(JwtProperties jwtProperties) {
        this.secretKey = jwtProperties.getTokenSecret();
        this.refreshTokenPeriod = jwtProperties.getRefreshTokenExpiry();
        this.accessTokenPeriod = jwtProperties.getTokenExpiry();
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        keyBytes = secretKey.getBytes();
        key = Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean verifyToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);

            return claims.getBody()
                .getExpiration()
                .after(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public String[] getRole(String token) {
        return new String[]{
            (String) Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("role")
        };
    }

    public String getUid(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }

    public long getExpiration(String token) {
        Date expiration = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody()
            .getExpiration();
        Long now = new Date().getTime();
        return (expiration.getTime() - now);
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

    public String tokenWithType(String accessToken, TokenType tokenType) {
        return tokenType.getTypeValue() + accessToken;
    }

    public String resolveToken(HttpServletRequest request) {
        Optional<String> tokenHeader = Optional.ofNullable(
            ((HttpServletRequest) request).getHeader(AUTHORIZATION));
        String token = tokenHeader.map(this::changeToToken).orElse(null);

        return token != null ? CoderUtil.decode(token) : null;
    }

    public void addAccessTokenToCookie(HttpServletResponse response, String accessToken,
        TokenType tokenType, String path) {
        Cookie cookie = setCookie(accessToken, tokenType);
        cookie.setPath(path);
        response.addCookie(cookie);
    }

    public void addAccessTokenToCookie(HttpServletResponse response, String accessToken,
        TokenType tokenType) {
        Cookie cookie = setCookie(accessToken, tokenType);
        response.addCookie(cookie);
    }

    private Cookie setCookie(String accessToken, TokenType tokenType) {
        Cookie cookie = new Cookie(AUTHORIZATION, CoderUtil.encode(this.tokenWithType(accessToken,
            tokenType)));
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge((int) this.getAccessTokenPeriod());

        return cookie;
    }
}
