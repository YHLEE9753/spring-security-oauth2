package com.practice.userservice.global.security;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.model.BlackListToken;
import com.practice.userservice.domain.model.RefreshToken;
import com.practice.userservice.domain.repository.BlackListTokenRedisRepo;
import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
import com.practice.userservice.global.token.TokenType;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenService tokenService;
    private final TokenGenerator tokenGenerator;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;
    private final BlackListTokenRedisRepo blackListTokenRedisRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        String token = resolveToken((HttpServletRequest) request);
        System.out.println(token);

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            // 블랙리스트에 존재하는 토큰인지 체크
            checkBlackList(token);

            // 토큰에서 email 과 role 를 가져온다.
            String email = tokenService.getUid(token);
            String[] roles = tokenService.getRole(token);

            setAuthenticationToSecurityCotextHolder(email, roles);



        } else if (token != null) {
            // 토큰이 유효하지 않은경우
            // refresh token 을 redis 에서 찾은 후 존재하는 경우 accessToken 을 재발급하여 제공한다.
            Optional<RefreshToken> optionalRefreshToken = refreshTokenRedisRepo.findById(token);
            if (optionalRefreshToken.isPresent()) {
                RefreshToken refreshToken = optionalRefreshToken.get();
                String email = tokenService.getUid(refreshToken.getRefreshTokenValue());
                String[] role = tokenService.getRole(refreshToken.getRefreshTokenValue());
                // accessToken 을 매핑되는 refreshToken 으로 갱신한 후 cookie 에 담은 후 contextholder 에 등록한다.
                String newAccessToken = newAccessToken(email, role);
                setAuthenticationToSecurityCotextHolder(email, role);
                writeTokenResponse(response, newAccessToken, TokenType.JWT_TYPE);
            }
        }
        // 토큰이 유효하지 않은경우 다음 필터로 이동한다.
        filterChain.doFilter(request, response);

    }

    private void checkBlackList(String token) {
        Optional<BlackListToken> blackListToken = blackListTokenRedisRepo.findById(
            tokenService.tokenWithType(token, TokenType.JWT_BLACKLIST));
        if(blackListToken.isPresent()){
            log.error("logout error - attack detected");
//            throw new IllegalArgumentException("logout error");
        }
    }

    private String resolveToken(HttpServletRequest request) {
        Optional<String> tokenHeader = Optional.ofNullable(
            request.getHeader(AUTHORIZATION));
        String token = tokenHeader.map(tokenService::changeToToken).orElse(null);
        if(token == null){
            return null;
        }
        return URLDecoder.decode(token, StandardCharsets.UTF_8);
    }

    private void writeTokenResponse(HttpServletResponse response, String accessToken,
        TokenType tokenType) throws IOException {
        String tokenWithType = tokenService.tokenWithType(accessToken, tokenType);

        Cookie cookie = new Cookie(AUTHORIZATION, URLEncoder.encode(tokenWithType, StandardCharsets.UTF_8));
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge((int) tokenService.getAccessTokenPeriod());

        response.addCookie(cookie);
    }

    private String newAccessToken(String uid, String[] role) {
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("role", role);
        Date now = new Date();

        return tokenGenerator.generateAccessToken(claims, now);
    }

    private void setAuthenticationToSecurityCotextHolder(String email, String[] roles) {
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        Arrays.stream(roles).forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role));
        });

        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(email, null, authorities);
        // SecurityContextHolder에 설정한다. - 이곳을 통해 thread 당 해당 유저의 정보를 확인
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}