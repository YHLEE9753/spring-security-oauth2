package com.practice.userservice.domain.controller;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.model.Member;
import com.practice.userservice.domain.service.BlackListTokenRedisService;
import com.practice.userservice.domain.service.MemberService;
import com.practice.userservice.domain.service.RefreshTokenRedisService;
import com.practice.userservice.global.token.TokenService;
import com.practice.userservice.global.token.TokenType;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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

    @GetMapping("/test")
    public String index() {
        return "Hello world";
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Optional<String> tokenHeader = Optional.ofNullable(
            ((HttpServletRequest) request).getHeader(AUTHORIZATION));
        String token = tokenHeader.map(tokenService::changeToToken).orElse(null);
        token = URLDecoder.decode(token, StandardCharsets.UTF_8);
        if (token != null) {
            String email = tokenService.getUid(token);
            String[] role = tokenService.getRole(token);
            long expiration = tokenService.getExpiration(token);
            refreshTokenRedisService.findAndDelete(token);

            blackListTokenRedisService.logout(
                tokenService.tokenWithType(token, TokenType.JWT_BLACKLIST),
                email, role, expiration
                );
        }

    }

    @GetMapping("/users")
    public ResponseEntity<List<Member>> getUsers() {
        return ResponseEntity
            .ok()
            .body(memberService.getUsers());
    }
}
