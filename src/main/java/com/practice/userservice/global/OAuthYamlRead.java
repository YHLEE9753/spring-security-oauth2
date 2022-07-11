package com.practice.userservice.global;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "app.jwt")
@Component
@Getter
@Setter
public class OAuthYamlRead {
    private String tokenSecret;
    private long tokenExpiry;
    private long refreshTokenExpiry;
}
