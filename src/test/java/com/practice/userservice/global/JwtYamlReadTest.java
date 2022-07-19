package com.practice.userservice.global;

import com.practice.userservice.global.token.JwtYamlRead;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class JwtYamlReadTest {
    @Autowired
    private JwtYamlRead jwtYamlRead;

    @Test
    void yamlFileTest () {
        // given
        // when
        // then
        System.out.println(jwtYamlRead.getTokenExpiry());
        System.out.println(jwtYamlRead.getRefreshTokenExpiry());
        System.out.println(jwtYamlRead.getTokenSecret());
    }
}