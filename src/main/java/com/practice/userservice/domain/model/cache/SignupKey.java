package com.practice.userservice.domain.model.cache;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Getter
@RedisHash(value = "signupKey")
public class SignupKey {
    @Id
    private String email;
    private String nickname;
    private String profileImageUrl;

    @TimeToLive
    private Long expiration;

    public SignupKey(String email, String nickname, String profileImageUrl, Long expiration) {
        this.email = email;
        this.nickname = nickname;
        this.profileImageUrl = profileImageUrl;
        this.expiration = expiration;
    }
}
