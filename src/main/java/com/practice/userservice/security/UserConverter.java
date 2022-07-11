package com.practice.userservice.security;

import com.practice.userservice.domain.User;

public class UserConverter {
    public static UserAuthenticationDto toDto(User user) {
        return UserAuthenticationDto.builder()
            .email(user.getUsername())
            .name(user.getName())
            .picture(user.getPassword())
            .build();
    }
}
