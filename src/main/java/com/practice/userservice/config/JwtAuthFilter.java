package com.practice.userservice.config;

import com.practice.userservice.service.TokenService;
import java.io.IOException;
import java.util.Arrays;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

@RequiredArgsConstructor
public class JwtAuthFilter extends GenericFilterBean {
    private final TokenService tokenService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException, ServletException {
        String token = ((HttpServletRequest)request).getHeader("Auth");

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            String email = tokenService.getUid(token);

            // DB연동을 안했으니 이메일 정보로 유저를 만들어주겠습니다
            UserDto userDto = UserDto.builder()
                .email(email)
                .name("이름")
                .picture("프로필 이미지").build();

            Authentication auth = getAuthentication(userDto);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }

    // UsernamePasswordAuthenticationToken 생성
    public Authentication getAuthentication(UserDto member) {
        return new UsernamePasswordAuthenticationToken(member, "",
            Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
    }
}