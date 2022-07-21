package com.practice.userservice.global.token;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "app.jwt")
@Component
@Getter
@Setter
public class JwtProperties {
    private String header;
    private String issuer;
    private String tokenSecret;
    private long tokenExpiry;
    private long refreshTokenExpiry;
}
