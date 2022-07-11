package com.practice.userservice.api;

import static com.practice.userservice.domain.Role.ROLE_USER;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.service.Token;
import com.practice.userservice.service.TokenService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/token")
public class TokenController {
    private final TokenService tokenService;

    @GetMapping("/expired")
    public String auth() {
        throw new RuntimeException();
    }

    @PostMapping("/refresh")
    public String refreshAuth(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = request.getHeader("Refresh");

        if (refreshToken != null && tokenService.verifyToken(refreshToken)) {
            String email = tokenService.getUid(refreshToken);
            Token newToken = tokenService.generateToken(email, ROLE_USER.stringValue);

            response.addHeader(AUTHORIZATION, newToken.getAccessToken());
            response.addHeader("Refresh", newToken.getRefreshToken());
            response.setContentType("application/json;charset=UTF-8");

            return "HAPPY NEW TOKEN";
        }

        throw new RuntimeException();
    }
}