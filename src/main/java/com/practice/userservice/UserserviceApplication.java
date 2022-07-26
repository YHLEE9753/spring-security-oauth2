package com.practice.userservice;

import com.practice.userservice.global.cache.repository.BlackListTokenRedisRepo;
import com.practice.userservice.global.cache.repository.RefreshTokenRedisRepo;
import com.practice.userservice.global.cache.repository.TemporaryMemberRedisRepo;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class UserserviceApplication {

    public static void main(String[] args) {
        SpringApplication.run(UserserviceApplication.class, args);
    }

    @Bean
    CommandLineRunner run(
        RefreshTokenRedisRepo refreshTokenRedisRepo,
        BlackListTokenRedisRepo blackListTokenRedisRepo,
        TemporaryMemberRedisRepo temporaryMemberRedisRepo) {
        return args -> {
            refreshTokenRedisRepo.deleteAll();
            blackListTokenRedisRepo.deleteAll();
            temporaryMemberRedisRepo.deleteAll();
        };
    }
}
