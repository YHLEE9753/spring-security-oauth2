package com.practice.userservice.security.filter;

import static com.practice.userservice.domain.Role.ROLE_USER;
import static java.lang.String.format;

import com.practice.userservice.domain.Role;
import com.practice.userservice.domain.User;
import com.practice.userservice.security.UserAuthenticationDto;
import com.practice.userservice.security.UserConverter;
import com.practice.userservice.service.TokenService;
import com.practice.userservice.service.UserService;
import com.practice.userservice.utils.TokenUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import javax.persistence.EntityNotFoundException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final TokenService tokenService;
    private final UserService userService;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException, ServletException {
        String token = ((HttpServletRequest)request).getHeader("Auth");
        log.info("hello");
        log.info("{}", token);

        // 토큰이 있는지, 유효한지 검증
        if (token != null && tokenService.verifyToken(token)) {
            log.info("Let's go!");
            // DB 연동을 안했으니 이메일 정보로 유저를 만들어주겠습니다.
            String username = tokenService.getUid(token);
            String[] roles = tokenService.getRole(token);

            // 사용자가 인증되었고 토큰이 유효하므로 암호는 필요하지 않는다.
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            Arrays.stream(roles).forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role));
                log.info("role");
            });
            UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
            // SecurityContextHolder에 설정한다. - 이것이 유저이름 역할이다 여기를 접근하여 판단할 것이다.
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            // DB 연동을 했으니 DB 에서 찾아오겠습니다.
//            User user = userService.getUser(email)
//                .orElseThrow(() -> new EntityNotFoundException(
//                    format("There is no User entity by userName. userName : {}", email)
//                ));
//            UserAuthenticationDto userAuthenticationDto = UserConverter.toDto(username, role);
//
//            Authentication auth = getAuthentication(userAuthenticationDto);
//            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }

    // UsernamePasswordAuthenticationToken 생성
    public Authentication getAuthentication(UserAuthenticationDto member) {
        return new UsernamePasswordAuthenticationToken(member, "",
            Arrays.asList(new SimpleGrantedAuthority(ROLE_USER.name)));
    }
}