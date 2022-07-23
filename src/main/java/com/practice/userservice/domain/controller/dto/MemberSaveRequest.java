package com.practice.userservice.domain.controller.dto;


import javax.validation.constraints.NotBlank;
import lombok.Builder;

public record MemberSaveRequest(
    @NotBlank
    String career,

    String githubUrl,

    String blogUrl
) {

}