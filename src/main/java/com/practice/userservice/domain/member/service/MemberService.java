package com.practice.userservice.domain.member.service;

import static com.practice.userservice.domain.member.model.Role.ROLE_USER;

import com.practice.userservice.domain.member.controller.dto.MemberResponse;
import com.practice.userservice.domain.member.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.member.model.Email;
import com.practice.userservice.domain.member.model.Member;
import com.practice.userservice.domain.member.repository.MemberRepo;
import com.practice.userservice.global.cache.model.TemporaryMember;
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
        return memberRepo.findByEmail(email);
    }

    @Transactional(readOnly = true)
    public List<Member> getUsers() {
        return memberRepo.findAll();
    }

    @Transactional
    public MemberResponse signup(MemberSaveRequest memberSaveRequest,
        TemporaryMember temporaryMember) {
        Member member = memberRepo.save(Member.builder()
            .email(memberSaveRequest.email())
            .nickname(memberSaveRequest.nickname())
            .profileImageUrl(temporaryMember.getImageUrl())
            .career(memberSaveRequest.career())
            .githubUrl(memberSaveRequest.githubUrl())
            .blogUrl(memberSaveRequest.blogUrl())
            .role(ROLE_USER)
            .build());

        return MemberResponse.builder()
            .memberId(member.getMemberId())
            .email(memberSaveRequest.email())
            .build();
    }
}
