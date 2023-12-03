package com.example.spring.security.oauth2.controller;

import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.servlet.OAuth2ClientAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = OAuth2ClientController.class, excludeAutoConfiguration = {OAuth2ClientAutoConfiguration.class})
@ExtendWith(SpringExtension.class)
public class OAuth2ClientControllerTest {

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockBean
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private OAuth2ClientController controller;

    private MockMvc mockMvc;

    @BeforeEach
    @SneakyThrows
    public void setup() {
        MockitoAnnotations.openMocks(this);

        this.mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    @WithMockUser
    public void testGetClientRegistration() throws Exception {
        String clientId = "testClient";
        when(clientRegistrationRepository.findByRegistrationId(clientId)).thenReturn(mock(ClientRegistration.class));

        mockMvc.perform(get("/oauth2/clients/" + clientId))
                .andExpect(status().isOk());

        verify(clientRegistrationRepository).findByRegistrationId(clientId);
    }

    @Test
    public void testGetAccessToken() throws Exception {
        String clientId = "testClient";
        String userName = "user";

        OAuth2AuthorizedClient client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(mock(OAuth2AccessToken.class));
        when(authorizedClientService.loadAuthorizedClient(clientId, userName)).thenReturn(client);

        Authentication authentication = mock(Authentication.class);
        when(authentication.getName()).thenReturn(userName);

        mockMvc.perform(get("/oauth2/access-token/" + clientId).principal(authentication))
                .andExpect(status().isOk());

        verify(authorizedClientService).loadAuthorizedClient(clientId, userName);
    }

    @Test
    public void testGetOidcUserPrincipal() throws Exception {

        HandlerMethodArgumentResolver methodArgumentResolver = mock(HandlerMethodArgumentResolver.class);

        OidcUser oidcUser = getOidcUser();

        given(methodArgumentResolver.resolveArgument(any(), any(), any(), any())).willReturn(oidcUser);
        given(methodArgumentResolver.supportsParameter(argThat(arg ->  OidcUser.class.isAssignableFrom(arg.getParameterType())))).willReturn(true);

        this.mockMvc = MockMvcBuilders.standaloneSetup(controller).setCustomArgumentResolvers(methodArgumentResolver).build();

        mockMvc.perform(get("/oauth2/oidc-principal"))
                .andExpect(status().isOk());
    }

    @Test
    public void testGetOAuth2UserPrincipal() throws Exception {

        HandlerMethodArgumentResolver methodArgumentResolver = mock(HandlerMethodArgumentResolver.class);

        OAuth2User user = getOAuthUser();

        given(methodArgumentResolver.resolveArgument(any(), any(), any(), any())).willReturn(user);
        given(methodArgumentResolver.supportsParameter(argThat(arg ->  OAuth2User.class.isAssignableFrom(arg.getParameterType())))).willReturn(true);

        this.mockMvc = MockMvcBuilders.standaloneSetup(controller).setCustomArgumentResolvers(methodArgumentResolver).build();

        mockMvc.perform(get("/oauth2/oauth-principal"))
                .andExpect(status().isOk());
    }


    private static OidcUser getOidcUser() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "123456"); // A dummy subject identifier

        OidcIdToken token = new OidcIdToken("tokenValue", Instant.now(), Instant.now().plusSeconds(60), attributes);

        OidcUser oidcUser = new DefaultOidcUser(Collections.emptyList(), token);
        return oidcUser;
    }

    private static OAuth2User getOAuthUser() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "123456"); // A dummy subject identifier

        OAuth2User user = new DefaultOAuth2User(Collections.emptyList(), attributes, "sub");
        return user;
    }
}

