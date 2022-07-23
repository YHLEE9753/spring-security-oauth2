package com.practice.userservice.domain.controller;


import static com.practice.userservice.domain.model.Role.ROLE_USER;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.controller.dto.MemberResponse;
import com.practice.userservice.domain.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.model.Member;
import com.practice.userservice.domain.model.cache.RefreshToken;
import com.practice.userservice.domain.model.cache.SignupKey;
import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
import com.practice.userservice.domain.repository.SignupKeyRedisRepo;
import com.practice.userservice.domain.service.BlackListTokenRedisService;
import com.practice.userservice.domain.service.MemberService;
import com.practice.userservice.domain.service.RefreshTokenRedisService;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
import com.practice.userservice.global.token.TokenType;
import com.practice.userservice.global.token.Tokens;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final TokenService tokenService;
    private final BlackListTokenRedisService blackListTokenRedisService;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final SignupKeyRedisRepo signupKeyRedisRepo;
    private final TokenGenerator tokenGenerator;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;

    @GetMapping("/test")
    public String index() {
        return "Hello world";
    }

    @PostMapping("/signup")
    public ResponseEntity<MemberResponse> singup(
        HttpServletRequest request,
        HttpServletResponse response,
        @Valid @RequestBody MemberSaveRequest memberSaveRequest
    ) throws IOException {
        String email = URLDecoder.decode(request.getHeader(AUTHORIZATION), StandardCharsets.UTF_8);
        Optional<SignupKey> signupKey = signupKeyRedisRepo.findById(email);// 리팩터링 필요
        if(!signupKey.isPresent()){
            throw new RuntimeException("url attack detected");
        }
        MemberResponse memberResponse = memberService.signup(memberSaveRequest, signupKey.get());
        // 이미 회원가입 한 유저의 경우 토큰을 refreshToken 저장 후 accessToken 쿠키 전달
        Tokens tokens = tokenGenerator.generateTokens(email, ROLE_USER.stringValue);
        saveRefreshTokenToRedis(tokens);

        // cookie 로 전달
        String accessToken = tokens.getAccessToken();
        addAccessTokenToCookie(response, accessToken, TokenType.JWT_TYPE);
        System.out.println("!!");
        System.out.println(tokenService.tokenWithType(accessToken, TokenType.JWT_TYPE));

        return ResponseEntity.created(
            URI.create("/api/v1/loginHome")).
            body(memberResponse);
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String token = resolveToken(request);
        System.out.println("logout start");
        if (token != null) {
            String email = tokenService.getUid(token);
            String[] role = tokenService.getRole(token);
            long expiration = tokenService.getExpiration(token);
            refreshTokenRedisService.findAndDelete(token);
            System.out.println(expiration);
            blackListTokenRedisService.logout(
                tokenService.tokenWithType(token, TokenType.JWT_BLACKLIST), expiration);
            System.out.println("logout success");
        }

    }

    @GetMapping("/users")
    public ResponseEntity<List<Member>> getUsers() {
        return ResponseEntity
            .ok()
            .body(memberService.getUsers());
    }


    private String resolveToken(HttpServletRequest request) {
        Optional<String> tokenHeader = Optional.ofNullable(
            ((HttpServletRequest) request).getHeader(AUTHORIZATION));
        String token = tokenHeader.map(tokenService::changeToToken).orElse(null);
        return URLDecoder.decode(token, StandardCharsets.UTF_8);
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

        response.addCookie(cookie);
    }
}
