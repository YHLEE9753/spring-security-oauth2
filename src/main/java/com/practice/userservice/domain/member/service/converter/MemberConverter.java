package com.practice.userservice.domain.member.service.converter;

import com.practice.userservice.domain.member.controller.dto.MemberResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
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
