package com.practice.userservice.domain.member.controller.dto;

import lombok.Builder;

@Builder
public record MemberSaveRequest(
    String email,
    String nickname,
    String imageUrl,
    String career,
    String githubUrl,
    String blogUrl
) {

}