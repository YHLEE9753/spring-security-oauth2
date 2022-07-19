package com.practice.userservice.global.security;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.model.RefreshToken;
import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        Optional<String> tokenHeader = Optional.ofNullable(((HttpServletRequest)request).getHeader(AUTHORIZATION));
        String token = tokenHeader.isPresent() ? tokenService.changeToToken(tokenHeader.get()) : null;

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            // 토큰에서 email 과 role 를 가져온다.
            String email = tokenService.getUid(token);
            String[] roles = tokenService.getRole(token);

            setAuthenticationToSecurityCotextHolder(email, roles);

        }else if(token != null){
            // 토큰이 유효하지 않은경우
            // refresh token 을 redis 에서 찾은 후 존재하는 경우 accessToken 을 재발급하여 제공한다.
            RefreshToken refreshToken = refreshTokenRedisRepo.findById(token).get();
            if(refreshToken != null){
                String uid = tokenService.getUid(token);
                String[] role = tokenService.getRole(token);
                // accessToken 을 매핑되는 refreshToken 으로 갱신한 후 cookie 에 담은 후 contextholder 에 등록한다.
                String newAccessToken = refreshAccessToken(uid, role);
                setAccessTokenToCookie(response, newAccessToken);
                setAuthenticationToSecurityCotextHolder(uid, role);
            }
        }
        // 토큰이 유효하지 않은경우 다음 필터로 이동한다.
        filterChain.doFilter(request, response);

    }

    private void setAccessTokenToCookie(HttpServletResponse response, String newAccessToken) {
        Cookie cookie = new Cookie("accessToken", newAccessToken);
        cookie.setDomain("localhost");

        // 전달 url 의 경로를 어떻게 설정하지??

        cookie.setPath("/main");
        cookie.setMaxAge((int) tokenService.getAccessTokenPeriod());
        response.addCookie(cookie);
    }

    private String refreshAccessToken(String uid, String[] role) {
        Claims claims = Jwts.claims().setSubject(uid);
        claims.put("role", role);
        Date now = new Date();

        String newAccessToken = tokenGenerator.generateAccessToken(claims, now);

        return newAccessToken;
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