package com.practice.userservice.global;

import com.practice.userservice.global.token.JwtProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JwtPropertiesTest {
    @Autowired
    private JwtProperties jwtProperties;

    @Test
    void yamlFileTest () {
        // given
        // when
        // then
        System.out.println(jwtProperties.getTokenExpiry());
        System.out.println(jwtProperties.getRefreshTokenExpiry());
        System.out.println(jwtProperties.getTokenSecret());
    }
}