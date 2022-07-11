package com.practice.userservice.global;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class OAuthYamlReadTest {
    @Autowired
    private OAuthYamlRead oAuthYamlRead;

    @Test
    void yamlFileTest () {
        // given
        // when
        // then
        System.out.println(oAuthYamlRead.getTokenExpiry());
        System.out.println(oAuthYamlRead.getRefreshTokenExpiry());
        System.out.println(oAuthYamlRead.getTokenSecret());
    }
}