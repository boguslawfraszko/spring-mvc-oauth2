package com.example.spring.security.springmvcoauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
public class OAuth2ClientController {
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/clients/{name}")
    public ClientRegistration index(@PathVariable("name") String name) {
        ClientRegistration clientRegistration =
                this.clientRegistrationRepository.findByRegistrationId(name);
        return clientRegistration;
    }
}
