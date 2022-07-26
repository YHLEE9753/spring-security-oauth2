package com.practice.userservice.global.cache.controller;

import com.practice.userservice.global.cache.model.BlackListToken;
import com.practice.userservice.global.cache.model.RefreshToken;
import com.practice.userservice.global.cache.repository.BlackListTokenRedisRepo;
import com.practice.userservice.global.cache.repository.RefreshTokenRedisRepo;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/redis")
@RequiredArgsConstructor
public class RedisController {

    private final BlackListTokenRedisRepo blackListTokenRedisRepo;
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;


    @GetMapping("/refresh")
    public List<List<String>> refresh() {
        List<List<String>> list = new ArrayList<>();
        if (refreshTokenRedisRepo.count() != 0L) {
            Iterator<RefreshToken> iterator = refreshTokenRedisRepo.findAll().iterator();
            while (iterator.hasNext()) {
                RefreshToken token = iterator.next();
                List<String> tokenDetail = new ArrayList<>();
                tokenDetail.add(token.getAccessTokenValue());
                tokenDetail.add(token.getRefreshTokenValue());
                tokenDetail.add(token.getExpiration().toString());
                tokenDetail.add(token.getCreatedTime().toString());
                tokenDetail.add(token.getExpirationTime().toString());
                list.add(tokenDetail);
            }
        }
        return list;
    }

    @GetMapping("/blackList")
    public List<List<String>> blackList() {
        List<List<String>> list = new ArrayList<>();
        if (blackListTokenRedisRepo.count() != 0L) {
            Iterator<BlackListToken> iterator = blackListTokenRedisRepo.findAll().iterator();
            while (iterator.hasNext()) {
                BlackListToken token = iterator.next();
                List<String> tokenDetail = new ArrayList<>();
                tokenDetail.add(token.getBlackListToken());
                tokenDetail.add(token.getExpiration().toString());
                list.add(tokenDetail);
            }
        }
        return list;
    }
}
