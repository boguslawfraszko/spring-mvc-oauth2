package com.example.spring.security.springmvcoauth2.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "oauth2-login";
    }

    @GetMapping("/logout")
    public String performLogout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws ServletException {
        request.logout();
        return "redirect:/login";
    }

    @GetMapping("/error")
    public String error(HttpServletRequest request) {
        System.out.println(request.getRequestURI());
        return null;
    }
}
