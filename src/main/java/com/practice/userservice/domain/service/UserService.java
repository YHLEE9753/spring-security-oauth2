package com.practice.userservice.domain.service;

import com.practice.userservice.domain.model.Member;
import java.util.List;
import java.util.Optional;

public interface UserService {
    Member saveUser(Member member);
    Optional<Member> getUser(String username);
    List<Member> getUsers();
    void logout(String accessToken);
}