package com.practice.userservice.domain.member.controller.mapper;

import com.practice.userservice.domain.member.controller.dto.MemberSaveRequest;
import com.practice.userservice.domain.member.service.dto.MemberDto;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;


@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class MemberMapper {

    public static MemberDto toMemberDto(MemberSaveRequest memberSaveRequest) {
        return MemberDto.builder()
            .career(memberSaveRequest.career())
            .githubUrl(memberSaveRequest.githubUrl())
            .blogUrl(memberSaveRequest.blogUrl())
            .build();
    }
}
