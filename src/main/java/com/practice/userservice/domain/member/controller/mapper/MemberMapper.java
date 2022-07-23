package com.practice.userservice.domain.member.controller.mapper;

import com.practice.userservice.domain.member.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.member.service.dto.MemberDto;

public class MemberMapper {
    public static MemberDto toMemberDto(MemberSaveRequest memberSaveRequest) {
        return MemberDto.builder()
            .career(memberSaveRequest.career())
            .githubUrl(memberSaveRequest.githubUrl())
            .blogUrl(memberSaveRequest.blogUrl())
            .build();
    }
}
