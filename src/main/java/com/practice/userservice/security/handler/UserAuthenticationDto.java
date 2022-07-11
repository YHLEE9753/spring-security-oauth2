package com.practice.userservice.security.handler;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class UserAuthenticationDto {
    private String email;
    private String name;
    private String picture;

    @Builder
    public UserAuthenticationDto(String email, String name, String picture) {
        this.email = email;
        this.name = name;
        this.picture = picture;
    }
}