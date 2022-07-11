package com.practice.userservice.security.filter;

import static com.practice.userservice.domain.Role.ROLE_USER;
import static java.lang.String.format;

import com.practice.userservice.domain.Role;
import com.practice.userservice.domain.User;
import com.practice.userservice.security.UserAuthenticationDto;
import com.practice.userservice.security.UserConverter;
import com.practice.userservice.service.TokenService;
import com.practice.userservice.service.UserService;
import java.io.IOException;
import java.util.Arrays;
import javax.persistence.EntityNotFoundException;
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
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final TokenService tokenService;
    private final UserService userService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException, ServletException {
        String token = ((HttpServletRequest)request).getHeader("Auth");

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            String email = tokenService.getUid(token);

            // DB 연동을 안했으니 이메일 정보로 유저를 만들어주겠습니다.
//            UserDto userDto = UserDto.builder()
//                .email(email)
//                .name("이름")
//                .picture("프로필 이미지").build();

            // DB 연동을 했으니 DB 에서 찾아오겠습니다.
            User user = userService.getUser(email)
                .orElseThrow(() -> new EntityNotFoundException(
                    format("There is no User entity by userName. userName : {}", email)
                ));
            UserAuthenticationDto userAuthenticationDto = UserConverter.toDto(user);

            Authentication auth = getAuthentication(userAuthenticationDto);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }

    // UsernamePasswordAuthenticationToken 생성
    public Authentication getAuthentication(UserAuthenticationDto member) {
        return new UsernamePasswordAuthenticationToken(member, "",
            Arrays.asList(new SimpleGrantedAuthority(ROLE_USER.name)));
    }
}