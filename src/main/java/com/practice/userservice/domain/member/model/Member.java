package com.practice.userservice.domain.member.model;

import com.practice.userservice.global.common.BaseTimeEntity;
import javax.persistence.Column;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Entity
@Getter
@NoArgsConstructor
public class Member extends BaseTimeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long memberId;

    @Column
    @NotNull
    private String nickname;

    @Embedded
    @NotNull
    private Email email;

    @Column
    @Enumerated(EnumType.STRING)
    private Career career;

    @Column
    private String profileImageUrl;

    @Column
    private String githubUrl;

    @Column
    private String blogUrl;

    @Column
    @NotNull
    private boolean isDeleted;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    public Member(String nickname, String email, String career, String profileImageUrl,
        String githubUrl,
        String blogUrl, Role role) {
        this.nickname = nickname;
        this.email = new Email(email);
        this.career = Career.toCareer(career);
        this.profileImageUrl = profileImageUrl;
        this.githubUrl = githubUrl;
        this.blogUrl = blogUrl;
        this.isDeleted = false;
        this.role = role;
    }
}
