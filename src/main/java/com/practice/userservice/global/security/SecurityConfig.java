package com.practice.userservice.global.security;

import static com.practice.userservice.domain.member.model.Role.ROLE_USER;
import static org.springframework.http.HttpMethod.GET;

import com.practice.userservice.global.cache.repository.RefreshTokenRedisRepo;
import com.practice.userservice.global.cache.service.BlackListTokenRedisService;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2MemberService oAuth2UserService;
    private final OAuth2SuccessHandler successHandler;
    private final TokenService tokenService;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;
    private final TokenGenerator tokenGenerator;
    private final BlackListTokenRedisService blackListTokenRedisService;

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, e) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.sendRedirect("/login");
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.sendRedirect("/login");
        };
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .rememberMe(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(
                sessionManagement -> sessionManagement
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeRequests(
                authorizeRequests -> authorizeRequests
                    .antMatchers("/api/**") // ?????? ?????????
                    .permitAll()

                    .antMatchers(GET, "/redis/**")
                    .hasAnyAuthority(ROLE_USER.stringValue)

                    .anyRequest().authenticated()
            )
            .oauth2Login(
                oauth2Login -> oauth2Login
                    .successHandler(successHandler)
                    .userInfoEndpoint()
                    .userService(oAuth2UserService)
            )
//            .exceptionHandling(
//                exceptionHandling -> {
//                    exceptionHandling.authenticationEntryPoint(authenticationEntryPoint());
//                    exceptionHandling.accessDeniedHandler(accessDeniedHandler());
//                }
//            )
            .addFilterBefore(
                new JwtAuthenticationFilter(tokenService, tokenGenerator, refreshTokenRedisRepo,
                    blackListTokenRedisService),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
