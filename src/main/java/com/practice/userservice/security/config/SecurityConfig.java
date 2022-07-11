package com.practice.userservice.security.config;

import static com.practice.userservice.domain.Role.ROLE_USER;
import static org.springframework.http.HttpMethod.GET;

import com.practice.userservice.security.filter.JwtAuthenticationFilter;
import com.practice.userservice.security.handler.OAuth2SuccessHandler;
import com.practice.userservice.service.CustomOAuth2UserService;
import com.practice.userservice.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
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

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable(); // rest api -> http 로그인 페이지 폼 X
        http.csrf().disable(); // rest api -> csrf 보안 X
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // 순서 1
        // 로그인은 누구나 접근 가능하게 + 토큰 갱신
        http.authorizeRequests().antMatchers("/token/**","/login/**").permitAll();

        // 순서 2
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority(ROLE_USER.stringValue);

        // 순서 3
        http.authorizeRequests().anyRequest().authenticated(); // 인증 필요

        http.oauth2Login().successHandler(successHandler).userInfoEndpoint().userService(oAuth2UserService);
        http.addFilterBefore(new JwtAuthenticationFilter(tokenService), UsernamePasswordAuthenticationFilter.class);
    }
}
