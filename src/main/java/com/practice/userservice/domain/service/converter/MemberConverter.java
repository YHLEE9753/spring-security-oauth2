package com.practice.userservice.domain.service.converter;

import com.practice.userservice.domain.controller.dto.MemberResponse;
import com.practice.userservice.domain.model.Member;
import com.practice.userservice.domain.service.dto.MemberDto;

public class MemberConverter {
//
//    public static Member toMember(MemberDto memberDto) {
//        return Member.builder()
//            .name(memberDto.name())
//            .password(new Password(memberDto.password()))
//            .phoneNumber(new PhoneNumber(memberDto.countryCode(), memberDto.phoneNumber()))
//            .birthDay(memberDto.birthday())
//            .email(new Email(memberDto.email()))
//            .address(memberDto.address())
//            .gender(memberDto.gender())
//            .build();
//    }

    public static MemberResponse toMemberResponse(Long memberId, String email) {
        return new MemberResponse(memberId, email);
    }
}
