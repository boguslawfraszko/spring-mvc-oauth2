package com.example.spring.security.springmvcoauth2.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "oauth2-login";
    }

    @GetMapping("/logout-success2")
    public String logoutSuccess() {
        return "oauth2-login";

    }

    @GetMapping("/logout2")
    public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws ServletException {
        request.logout();
        return null;
    }

    //@GetMapping("/error")
    public String error(HttpServletRequest request) throws IOException {
        System.out.println(request.getRequestURI());
        System.out.println(
                new BufferedReader(new InputStreamReader(request.getInputStream()))
                        .lines()
                        .collect(Collectors.joining(" "))
        );

        return null;
    }
}
