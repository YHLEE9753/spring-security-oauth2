package com.practice.userservice.domain.service;

import com.practice.userservice.domain.model.Member;
import com.practice.userservice.domain.model.RefreshToken;
import com.practice.userservice.domain.repository.MemberRepo;
import com.practice.userservice.global.token.TokenService;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepo memberRepo;

    @Transactional
    public Member saveUser(Member member) {
        log.info("Saving new user {} to the database", member.getName());
        return memberRepo.save(member);
    }

    @Transactional(readOnly = true)
    public Optional<Member> getUser(String email) {
        log.info("Fetching user {}", email);
        return memberRepo.findByEmail(email);
    }

    @Transactional(readOnly = true)
    public List<Member> getUsers() {
        log.info("Fetching all users");
        return memberRepo.findAll();
    }
}
