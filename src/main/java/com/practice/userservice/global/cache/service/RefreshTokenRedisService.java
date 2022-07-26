package com.practice.userservice.global.cache.service;

import com.practice.userservice.global.cache.model.RefreshToken;
import com.practice.userservice.global.cache.repository.RefreshTokenRedisRepo;
import com.practice.userservice.global.token.Tokens;
import java.util.Date;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenRedisService {

    private final RefreshTokenRedisRepo refreshTokenRedisRepo;

    public void findAndDelete(String accessToken) {
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRedisRepo.findById(accessToken);
        if (optionalRefreshToken.isPresent()) {
            RefreshToken refreshToken = optionalRefreshToken.get();
            refreshTokenRedisRepo.delete(refreshToken);
        }
    }

    public void save(Tokens tokens, long refreshPeriod) {
        Date now = new Date();
        RefreshToken refreshToken = new RefreshToken(
            tokens.getAccessToken(),
            tokens.getRefreshToken(),
            now,
            new Date(now.getTime() + refreshPeriod)
        );
        refreshTokenRedisRepo.save(refreshToken);
    }

}
