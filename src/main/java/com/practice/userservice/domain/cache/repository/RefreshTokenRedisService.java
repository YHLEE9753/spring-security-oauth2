package com.practice.userservice.domain.cache.repository;

import com.practice.userservice.domain.cache.model.RefreshToken;
import com.practice.userservice.domain.cache.repository.RefreshTokenRedisRepo;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RefreshTokenRedisService {
    private final RefreshTokenRedisRepo refreshTokenRedisRepo;

    public Optional<RefreshToken> findById(String id){
        return refreshTokenRedisRepo.findById(id);
    }

    public void delete(RefreshToken refreshToken){
        refreshTokenRedisRepo.delete(refreshToken);
    }

    public void findAndDelete(String accessToken){
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRedisRepo.findById(accessToken);
        if(optionalRefreshToken.isPresent()){
            RefreshToken refreshToken = optionalRefreshToken.get();
            refreshTokenRedisRepo.delete(refreshToken);
        }
    }
}
