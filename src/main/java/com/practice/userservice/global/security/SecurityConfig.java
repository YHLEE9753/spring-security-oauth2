package com.practice.userservice.global.security;

import static com.practice.userservice.domain.model.Role.ROLE_USER;
import static org.springframework.http.HttpMethod.GET;

import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
import com.practice.userservice.domain.service.CustomOAuth2UserService;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final TokenService tokenService;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;
    private final TokenGenerator tokenGenerator;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .httpBasic(
                httpBasic -> httpBasic.disable()
            )
            .csrf(
                csrf -> csrf.disable()
            )
            .sessionManagement(
                sessionManagement -> sessionManagement
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeRequests(
                authorizeRequests -> authorizeRequests
                    .antMatchers("/token/**", "/login/**")
                    .permitAll()
                    .antMatchers(GET, "/api/user/**")
                    .hasAnyAuthority(ROLE_USER.stringValue)
                    .anyRequest().authenticated()
            )
            .logout(
                logout -> logout.logoutSuccessUrl("/login")
            )
            .oauth2Login(
                oauth2Login -> oauth2Login
                    .successHandler(successHandler)
                    .userInfoEndpoint()
                    .userService(oAuth2UserService)
            )
            .addFilterBefore(new JwtAuthenticationFilter(tokenService, tokenGenerator, refreshTokenRedisRepo),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
