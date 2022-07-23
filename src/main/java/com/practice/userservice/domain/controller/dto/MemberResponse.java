package com.practice.userservice.domain.controller.dto;

import lombok.Builder;

@Builder
public record MemberResponse (
    Long memberId,
    String email
){
}
