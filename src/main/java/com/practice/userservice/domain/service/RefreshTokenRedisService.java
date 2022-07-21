package com.practice.userservice.domain.service;

import com.practice.userservice.domain.model.RefreshToken;
import com.practice.userservice.domain.repository.RefreshTokenRedisRepo;
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
