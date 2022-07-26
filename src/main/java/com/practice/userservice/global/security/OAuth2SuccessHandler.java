package com.practice.userservice.global.security;

import static com.practice.userservice.domain.member.model.Role.*;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.member.model.Email;
import com.practice.userservice.global.cache.model.RefreshToken;
import com.practice.userservice.global.cache.model.TemporaryMember;
import com.practice.userservice.global.cache.repository.RefreshTokenRedisRepo;
import com.practice.userservice.domain.member.model.Member;
import com.practice.userservice.domain.member.service.MemberService;
import com.practice.userservice.global.cache.repository.TemporaryMemberRedisRepo;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenType;
import com.practice.userservice.global.token.Tokens;
import com.practice.userservice.global.token.TokenService;

import com.practice.userservice.global.util.CoderUtil;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
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
    private final TemporaryMemberRedisRepo temporaryMemberRedisRepo;
    private RedirectStrategy redirectStratgy = new DefaultRedirectStrategy();

    @Value("${app.oauth.domain}")
    private String domain;

    @Value("${app.oauth.signupPath}")
    private String signupPath;

    @Value("${app.oauth.loginSuccessPath}")
    private String loginSuccessPath;

    @Value("${app.oauth.signupTime}")
    private Long signupTime;

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
        Optional<Member> optionalMember = memberService.getUser(new Email(email));
        if (!optionalMember.isPresent()) {
            TemporaryMember temporaryMember = new TemporaryMember(email, name, picture, signupTime);
            temporaryMemberRedisRepo.save(temporaryMember);

            String temporaryMemberEmail = temporaryMember.getEmail();

            String param1 = "?email=" + CoderUtil.encode(temporaryMemberEmail);
            String param2 = "&name=" + CoderUtil.encode(name);
            String targetURI = domain + signupPath + param1 + param2;
            redirectStratgy.sendRedirect(request, response, targetURI);
        } else {
            // 이미 회원가입 한 유저의 경우 토큰을 refreshToken 저장 후 accessToken 쿠키 전달
            Tokens tokens = tokenGenerator.generateTokens(email, ROLE_USER.stringValue);
            saveRefreshTokenToRedis(tokens);

            // cookie 로 전달
            addAccessTokenToCookie(response, tokens.getAccessToken(), TokenType.JWT_TYPE);
            redirectStratgy.sendRedirect(request, response, domain + loginSuccessPath);
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
        TokenType tokenType) {
        Cookie cookie = new Cookie(AUTHORIZATION,
            URLEncoder.encode(tokenService.tokenWithType(accessToken, tokenType),
                StandardCharsets.UTF_8));
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setMaxAge((int) tokenService.getAccessTokenPeriod());
        cookie.setPath(loginSuccessPath);

        response.addCookie(cookie);
    }
}
