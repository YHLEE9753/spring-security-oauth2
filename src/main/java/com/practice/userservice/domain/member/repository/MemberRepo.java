package com.practice.userservice.domain.member.repository;

import com.practice.userservice.domain.member.model.Email;
import com.practice.userservice.domain.member.model.Member;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepo extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(Email email);
}
