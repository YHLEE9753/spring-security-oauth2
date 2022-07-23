package com.practice.userservice.domain.member.service.dto;

import lombok.Builder;

@Builder
public record MemberDto(
    String career,
    String githubUrl,
    String blogUrl
) {
}

