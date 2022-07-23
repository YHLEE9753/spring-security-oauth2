package com.practice.userservice;

import com.practice.userservice.domain.cache.repository.BlackListTokenRedisRepo;
import com.practice.userservice.domain.cache.repository.RefreshTokenRedisRepo;
import com.practice.userservice.domain.member.service.MemberService;
import com.practice.userservice.global.token.TokenGenerator;
import com.practice.userservice.global.token.TokenService;
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
        MemberService memberService,
        TokenService tokenService,
        TokenGenerator tokenGenerator,
        RefreshTokenRedisRepo refreshTokenRedisRepo,
        BlackListTokenRedisRepo blackListTokenRedisRepo) {
        return args -> {
//            refreshTokenRedisRepo.deleteAll();
//            blackListTokenRedisRepo.deleteAll();
//
//            // 애플리케이션이 초기화 된 후 실행 되는 부분
//            String email = "test@test.com";
//            Member member = Member.builder()
//                .nickname("테스트")
//                .email(email)
//                .profileImageUrl("test.s3.com")
//                .role(Role.ROLE_USER)
//                .build();
//	        memberService.saveUser(member);
//
//			Tokens tokens = tokenGenerator.generateTokens(email, Role.ROLE_USER.stringValue);
//
//            Date now = new Date();
//            RefreshToken refreshToken = new RefreshToken(
//                tokens.getAccessToken(),
//                tokens.getRefreshToken(),
//                now,
//                new Date(now.getTime() + tokenService.getRefreshPeriod())
//            );
//            refreshTokenRedisRepo.save(refreshToken);
//            System.out.println(tokens.getAccessToken());
		};
    }
}
