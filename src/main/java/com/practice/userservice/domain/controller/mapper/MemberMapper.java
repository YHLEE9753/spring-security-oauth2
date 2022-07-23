package com.practice.userservice.domain.controller.mapper;

import com.practice.userservice.domain.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.service.dto.MemberDto;

public class MemberMapper {
    public static MemberDto toMemberDto(MemberSaveRequest memberSaveRequest) {
        return MemberDto.builder()
            .career(memberSaveRequest.career())
            .githubUrl(memberSaveRequest.githubUrl())
            .blogUrl(memberSaveRequest.blogUrl())
            .build();
    }
}
