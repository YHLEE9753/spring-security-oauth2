package com.practice.userservice.global.security.filter;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.global.token.TokenService;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
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

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        Optional<String> tokenHeader = Optional.ofNullable(((HttpServletRequest)request).getHeader(AUTHORIZATION));
        String token = tokenHeader.isPresent() ? tokenService.changeToToken(tokenHeader.get()) : null;

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            // 토큰에서 username 과 role 를 가져온다.
            String username = tokenService.getUid(token);
            String[] roles = tokenService.getRole(token);

            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            Arrays.stream(roles).forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role));
            });
            UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
            // SecurityContextHolder에 설정한다. - 이곳을 통해 thread 당 해당 유저의 정보를 확인
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        }
        // 토큰이 유효하지 않은경우 다음 필터로 이동한다.
        filterChain.doFilter(request, response);

    }
}