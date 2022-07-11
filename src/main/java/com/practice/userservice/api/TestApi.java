package com.practice.userservice.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestApi {
    @GetMapping("/test")
    public String index(){
        return "Hello world";
    }
}
