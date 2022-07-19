package com.practice.userservice.global.security;

import static com.practice.userservice.domain.model.Role.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.userservice.domain.model.Member;
import com.practice.userservice.domain.model.RefreshToken;
import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.Tokens;
import com.practice.userservice.global.token.TokenService;
import com.practice.userservice.domain.service.UserService;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
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
    private final TokenGenerator tokenGenerator;
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;
    private final UserService userService;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;

    private RedirectStrategy redirectStratgy = new DefaultRedirectStrategy();

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
                Member.builder()
                    .email(email)
                    .name(name)
                    .picture(picture)
                    .role(ROLE_USER)
                    .build()
            ));

        // access token 과 refresh token 을 생성
        Tokens tokens = tokenGenerator.generateTokens(email, ROLE_USER.stringValue);

        // refresh token 은 redis 에 저장
        Date now = new Date();
        RefreshToken refreshToken = new RefreshToken(
            tokens.getAccessToken(),
            tokens.getRefreshToken(),
            now,
            new Date(now.getTime() + 7776000000L)
        );
        refreshTokenRedisRepo.save(refreshToken);

        // access token 은 cookie 로 전달,
        Cookie cookie = new Cookie("accessToken", tokens.getAccessToken());
        cookie.setDomain("localhost");
        cookie.setPath("/main");
        cookie.setMaxAge((int) tokenService.getAccessTokenPeriod());
        response.addCookie(cookie);
        String targetUrl = "http://localhost:3000/main";
        redirectStratgy.sendRedirect(request, response, targetUrl);
    }
}