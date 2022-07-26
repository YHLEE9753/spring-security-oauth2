package com.practice.userservice.global.cache.model;

import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;

@Getter
@RedisHash(value = "blackListToken")
public class BlackListToken {

    @Id
    private String blackListToken;

    @TimeToLive
    private Long expiration;

    public BlackListToken(String blackListToken, Long expiration) {
        this.blackListToken = blackListToken;
        this.expiration = expiration;
    }
}
