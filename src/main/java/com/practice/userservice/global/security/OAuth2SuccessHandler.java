package com.practice.userservice.global.security;

import static com.practice.userservice.domain.model.Role.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.model.Email;
import com.practice.userservice.domain.model.cache.RefreshToken;
import com.practice.userservice.domain.model.cache.SignupKey;
import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
import com.practice.userservice.domain.repository.SignupKeyRedisRepo;
import com.practice.userservice.domain.service.MemberService;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenType;
import com.practice.userservice.global.token.Tokens;
import com.practice.userservice.global.token.TokenService;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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
    private final MemberService memberService;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;
    private final SignupKeyRedisRepo signupKeyRedisRepo;
    private RedirectStrategy redirectStratgy = new DefaultRedirectStrategy();

    @Value("${app.oauth.domain}")
    private String domain;

    @Value("${app.oauth.sign-up-path}")
    private String signUpPath;

    @Value("${app.oauth.login-path}")
    private String loginPath;

    @Value("${app.oauth.sign-up-time}")
    private int signUpTime;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {
        // 인증 된 principal 를 가지고 온다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String picture = (String) attributes.get("picture");

        // 최초 로그인이라면 추가 회원가입 처리를 한다.
        if (!memberService.getUser(new Email(email)).isPresent()) {
            SignupKey signupKey = new SignupKey(email, name, picture, 500000L);
            signupKeyRedisRepo.save(signupKey);

            System.out.println("추가 로그인 추가");
            System.out.println(URLEncoder.encode(email, StandardCharsets.UTF_8));

            // email 을 쿠키로 전달
            customCookie(response, AUTHORIZATION, URLEncoder.encode(email, StandardCharsets.UTF_8), signUpTime);

            redirectStratgy.sendRedirect(request, response, domain+signUpPath);
        }else{
            // 이미 회원가입 한 유저의 경우 토큰을 refreshToken 저장 후 accessToken 쿠키 전달
            Tokens tokens = tokenGenerator.generateTokens(email, ROLE_USER.stringValue);
            saveRefreshTokenToRedis(tokens);

            // cookie 로 전달
            addAccessTokenToCookie(response, tokens.getAccessToken(), TokenType.JWT_TYPE);
            redirectStratgy.sendRedirect(request, response, domain+loginPath);
        }
    }

    private void saveRefreshTokenToRedis(Tokens tokens) {
        Date now = new Date();
        RefreshToken refreshToken = new RefreshToken(
            tokens.getAccessToken(),
            tokens.getRefreshToken(),
            now,
            new Date(now.getTime() + tokenService.getRefreshPeriod())
        );
        refreshTokenRedisRepo.save(refreshToken);
    }


    private void addAccessTokenToCookie(HttpServletResponse response, String accessToken,
        TokenType tokenType) throws IOException {
        Cookie cookie = new Cookie(AUTHORIZATION, URLEncoder.encode(tokenService.tokenWithType(accessToken, tokenType),StandardCharsets.UTF_8));
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge((int) tokenService.getAccessTokenPeriod());
        cookie.setPath(loginPath);

        response.addCookie(cookie);
    }

    private void customCookie(HttpServletResponse response, String key, String value, int time)
        throws IOException {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(time);
        cookie.setPath(signUpPath);

        response.addCookie(cookie);
    }
}