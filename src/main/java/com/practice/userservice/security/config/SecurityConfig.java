package com.practice.userservice.config;

import com.practice.userservice.security.filter.JwtAuthenticationFilter;
import com.practice.userservice.security.oauth.OAuth2SuccessHandler;
import com.practice.userservice.service.CustomOAuth2UserService;
import com.practice.userservice.service.TokenService;
import com.practice.userservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final TokenService tokenService;
    private final UserService userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable(); // rest api -> http 로그인 페이지 폼 X
        http.csrf().disable(); // rest api -> csrf 보안 X
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
            .antMatchers("/token/**").permitAll()
            .anyRequest().authenticated(); // 인증 필요
        http.oauth2Login().successHandler(successHandler).userInfoEndpoint().userService(oAuth2UserService);

        http.addFilterBefore(new JwtAuthenticationFilter(tokenService, userService), UsernamePasswordAuthenticationFilter.class);

    }
}