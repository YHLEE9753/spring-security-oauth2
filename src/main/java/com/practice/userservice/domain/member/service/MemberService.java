package com.practice.userservice.domain.member.service;

import com.practice.userservice.domain.member.controller.dto.MemberResponse;
import com.practice.userservice.domain.member.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.member.model.Email;
import com.practice.userservice.domain.member.model.Member;
import com.practice.userservice.domain.member.model.Role;
import com.practice.userservice.domain.cache.model.SignupKey;
import com.practice.userservice.domain.member.repository.MemberRepo;
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

    @Transactional(readOnly = true)
    public Optional<Member> getUser(Email email) {
        log.info("Fetching user {}", email);
        return memberRepo.findByEmail(email);
    }

    @Transactional(readOnly = true)
    public List<Member> getUsers() {
        log.info("Fetching all users");
        return memberRepo.findAll();
    }

    @Transactional
    public MemberResponse signup(MemberSaveRequest memberSaveRequest, SignupKey signupKey) {
        Member member = Member.builder()
            .nickname(signupKey.getNickname())
            .email(signupKey.getEmail())
            .career(memberSaveRequest.career())
            .profileImageUrl(signupKey.getProfileImageUrl())
            .githubUrl(memberSaveRequest.githubUrl())
            .blogUrl(memberSaveRequest.blogUrl())
            .role(Role.ROLE_USER)
            .build();

        log.info("Saving new user {} to the database", member.getNickname());
        Member savedMember = memberRepo.save(member);

        return MemberResponse.builder()
            .memberId(savedMember.getMemberId())
            .email(signupKey.getEmail())
            .build();

    }
}
