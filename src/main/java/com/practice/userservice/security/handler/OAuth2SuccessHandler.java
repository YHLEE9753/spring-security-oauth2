package com.practice.userservice.security.handler;

import static com.practice.userservice.domain.Role.*;
import static java.lang.String.format;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.userservice.security.UserAuthenticationDto;
import com.practice.userservice.domain.User;
import com.practice.userservice.security.UserRequestMapper;
import com.practice.userservice.service.Token;
import com.practice.userservice.service.TokenService;
import com.practice.userservice.service.UserService;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final TokenService tokenService;
    private final ObjectMapper objectMapper;
    private final UserService userService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication)
        throws IOException, ServletException {
        // 인증 된 principal 를 가지고 온다.
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        UserAuthenticationDto userAuthenticationDto = UserRequestMapper.toDto(oAuth2User);

        // 최초 로그인이라면 회원가입 처리를 한다.
        userService.getUser(userAuthenticationDto.getEmail())
            .orElseGet(() ->userService.saveUser(
                User.builder()
                    .username(userAuthenticationDto.getEmail())
                    .name(userAuthenticationDto.getName())
                    .build()
            ));

        // 토큰 생성
        Token token = tokenService.generateToken(userAuthenticationDto.getEmail(), ROLE_USER.name);
        log.info("{}", token);

        writeTokenResponse(response, token);
    }

    private void writeTokenResponse(HttpServletResponse response, Token token)
        throws IOException {
        response.setContentType("text/html;charset=UTF-8");

        response.addHeader("Auth", token.getToken());
        response.addHeader("Refresh", token.getRefreshToken());
        response.setContentType("application/json;charset=UTF-8");

        var writer = response.getWriter();
        writer.println(objectMapper.writeValueAsString(token));
        writer.flush();
    }
}