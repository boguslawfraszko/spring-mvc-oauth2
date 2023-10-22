package com.example.spring.security.springmvcoauth2.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
@Slf4j
public class OAuth2ClientController {
    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/clients/{name}")
    public ClientRegistration getClientRegistration(@PathVariable("name") String clientRegistrationId) {
        ClientRegistration clientRegistration =
                this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
        return clientRegistration;
    }

    @GetMapping("/access-token/{name}")
    public OAuth2AccessToken getAccessToken(Authentication authentication, @PathVariable("name") String clientRegistrationId) {
        log.info("authentication "+ authentication);
        OAuth2AuthorizedClient authorizedClient =
                this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, authentication.getName());

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        return accessToken;
    }
}
