package com.practice.userservice.security;

import com.practice.userservice.security.UserAuthenticationDto;
import java.util.Map;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class UserRequestMapper {
    public static UserAuthenticationDto toDto(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();
        return UserAuthenticationDto.builder()
            .email((String)attributes.get("email"))
            .name((String)attributes.get("name"))
            .picture((String)attributes.get("picture"))
            .build();
    }
}