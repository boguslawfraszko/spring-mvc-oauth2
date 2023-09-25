package com.example.spring.security.springmvcoauth2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    @GetMapping(value = "/", produces = "text/plain")
    public String home() {
        return "Hello World";
    }
}
