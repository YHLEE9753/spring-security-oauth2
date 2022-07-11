package com.practice.userservice.api;

import com.practice.userservice.domain.User;
import com.practice.userservice.service.UserService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserApi {
    private final UserService userService;

    @GetMapping("/test")
    public String index(){
        return "Hello world";
    }

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers() {
        return ResponseEntity
            .ok()
            .body(userService.getUsers());
    }
}