package com.practice.userservice.config;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

import com.practice.userservice.security.filter.JwtAuthenticationFilter;
import com.practice.userservice.security.oauth.OAuth2SuccessHandler;
import com.practice.userservice.service.CustomOAuth2UserService;
import com.practice.userservice.service.TokenService;
import com.practice.userservice.service.UserService;
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
    private final UserService userService;

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
        http.authorizeRequests().antMatchers(GET, "/api/user/**").hasAnyAuthority("ROLE_USER");

        // 순서 3
        http.authorizeRequests().anyRequest().authenticated(); // 인증 필요

        http.oauth2Login().successHandler(successHandler).userInfoEndpoint().userService(oAuth2UserService);
        http.addFilterBefore(new JwtAuthenticationFilter(tokenService, userService), UsernamePasswordAuthenticationFilter.class);
//        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class); // 인증이 맨앞에

    }
}
