package com.practice.userservice.domain.member.controller;


import static com.practice.userservice.domain.member.model.Role.ROLE_USER;

import com.practice.userservice.domain.member.controller.dto.MemberResponse;
import com.practice.userservice.domain.member.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.member.model.Member;
import com.practice.userservice.global.cache.model.TemporaryMember;
import com.practice.userservice.global.cache.service.BlackListTokenRedisService;
import com.practice.userservice.domain.member.service.MemberService;
import com.practice.userservice.global.cache.service.RefreshTokenRedisService;
import com.practice.userservice.global.cache.service.TemporaryMemberRedisService;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
import com.practice.userservice.global.token.TokenType;
import com.practice.userservice.global.token.Tokens;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;
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
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;
    private final TokenService tokenService;
    private final BlackListTokenRedisService blackListTokenRedisService;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final TemporaryMemberRedisService temporaryMemberRedisService;
    private final TokenGenerator tokenGenerator;

    @GetMapping("/login")
    public String index() {
        return "index.html";
    }

    @PostMapping("/signup")
    public ResponseEntity<MemberResponse> singup(
        HttpServletResponse response,
        @Valid @RequestBody MemberSaveRequest memberSaveRequest
    ) throws IOException {
        Optional<TemporaryMember> optionalMember = temporaryMemberRedisService.findById(
            memberSaveRequest.email());
        if (optionalMember.isEmpty()) {
            throw new RuntimeException("signup time is expired");
        }
        TemporaryMember temporaryMember = optionalMember.get();
        MemberResponse memberResponse = memberService.signup(memberSaveRequest, temporaryMember);
        // 이미 회원가입 한 유저의 경우 토큰을 refreshToken 저장 후 accessToken 쿠키 전달
        Tokens tokens = tokenGenerator.generateTokens(memberSaveRequest.email(),
            ROLE_USER.stringValue);

        refreshTokenRedisService.save(tokens, tokenService.getRefreshPeriod());

        // cookie 로 전달
        String accessToken = tokens.getAccessToken();
        System.out.println(accessToken);
        tokenService.addAccessTokenToCookie(response, accessToken, TokenType.JWT_TYPE);

        return ResponseEntity.created(
                URI.create("/api/v1/loginHome")).
            body(memberResponse);
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String token = tokenService.resolveToken(request);

        if (token != null) {
            long expiration = tokenService.getExpiration(token);

            refreshTokenRedisService.findAndDelete(token);
            blackListTokenRedisService.logout(
                tokenService.tokenWithType(token, TokenType.JWT_BLACKLIST), expiration);
        }
    }

    @GetMapping("/users")
    public ResponseEntity<List<Member>> getUsers() {
        return ResponseEntity
            .ok()
            .body(memberService.getUsers());
    }
}
