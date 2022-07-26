package com.practice.userservice.global.cache.service;

import com.practice.userservice.global.cache.model.TemporaryMember;
import com.practice.userservice.global.cache.repository.TemporaryMemberRedisRepo;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TemporaryMemberRedisService {

    private final TemporaryMemberRedisRepo temporaryMemberRedisRepo;

    public Optional<TemporaryMember> findById(String id) {
        return temporaryMemberRedisRepo.findById(id);
    }
}
