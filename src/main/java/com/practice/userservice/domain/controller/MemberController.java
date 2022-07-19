package com.practice.userservice.domain.controller;


import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import com.practice.userservice.domain.model.Member;
import com.practice.userservice.domain.service.UserService;
import java.util.List;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {
    private final UserService userService;

    @GetMapping("/test")
    public String index(){
        return "Hello world";
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response){
        // 1. accesstoken 을 통해 refreshtoken 을 제거한다.
        userService.logout(request.getHeader(AUTHORIZATION));
    }

    @GetMapping("/users")
    public ResponseEntity<List<Member>> getUsers() {
        return ResponseEntity
            .ok()
            .body(userService.getUsers());
    }
}
