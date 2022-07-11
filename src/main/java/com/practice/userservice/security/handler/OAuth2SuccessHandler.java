package com.practice.userservice.security.handler;

import static com.practice.userservice.domain.Role.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.userservice.domain.User;
import com.practice.userservice.service.Token;
import com.practice.userservice.service.TokenService;
import com.practice.userservice.service.UserService;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService;
    private final ObjectMapper objectMapper;
    private final UserService userService;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication)
        throws IOException, ServletException {
        // 인증 된 principal 를 가지고 온다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String picture = (String) attributes.get("picture");

        // 최초 로그인이라면 회원가입 처리를 한다.(User 로 회원가입)
        userService.getUser(email)
            .orElseGet(() -> userService.saveUser(
                User.builder()
                    .username(email)
                    .name(name)
                    .picture(picture)
                    .role(ROLE_USER)
                    .build()
            ));

        // 토큰 생성
        Token token = tokenService.generateToken(email, ROLE_USER.stringValue);

        writeTokenResponse(response, token);
    }

    private void writeTokenResponse(HttpServletResponse response, Token token)
        throws IOException {
        response.setContentType("text/html;charset=UTF-8");
//        response.addHeader(AUTHORIZATION, "Bearer " + token.getAccessToken());
        response.setContentType("application/json;charset=UTF-8");

        Cookie cookie = new Cookie("refreshToken",token.getRefreshToken());

        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) tokenService.getRefreshPeriod());

        response.addCookie(cookie);

        PrintWriter writer = response.getWriter();
        writer.println(objectMapper.writeValueAsString(token.getAccessToken()));
        writer.flush();
    }
}