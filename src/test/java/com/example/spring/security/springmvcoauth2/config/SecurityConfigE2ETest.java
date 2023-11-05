package com.example.spring.security.springmvcoauth2.config;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import(SecurityConfig.class)
@WebMvcTest
public class SecurityConfigE2ETest {

    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext context;

    @RegisterExtension
    static WireMockExtension wm1 = WireMockExtension.newInstance()
            .options(wireMockConfig().httpsPort(8089))
            .build();

    @BeforeEach
    public void setup() {

        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .alwaysDo(print())
                .build();
    }

    @Test
    @DisplayName("Should redirect to OAuth authorize url and with return url containing nounce ")
    public void testOAuth2Authorization() throws Exception {

        mockMvc.perform(get("/oauth2/authorization/test-oauth-provider").secure(true))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> {
                    String actualRedirectedUrl = result.getResponse().getRedirectedUrl();
                    assertTrue(actualRedirectedUrl.startsWith("https://localhost:8089/oauth/authorize"));
                    assertTrue(actualRedirectedUrl.contains("&redirect_uri=http://localhost/login/oauth2/code/test-oauth-provider&nonce="));
                });
    }

    @Test
    @DisplayName("Should return to login endpoint ")
    public void testReturnToOAuthLogin() throws Exception {

        String authorizeRedirectedUrl = mockMvc.perform(get("/oauth2/authorization/test-oauth-provider").secure(true))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> {
                    String actualRedirectedUrl = result.getResponse().getRedirectedUrl();
                    assertTrue(actualRedirectedUrl.startsWith("https://localhost:8089/oauth/authorize"));
                    assertTrue(actualRedirectedUrl.contains("&redirect_uri=http://localhost/login/oauth2/code/test-oauth-provider&nonce="));
                })
                .andReturn().getResponse().getRedirectedUrl();

        String state = UriComponentsBuilder.fromUriString(authorizeRedirectedUrl)
                .build()
                .getQueryParams()
                .getFirst("state");

        String path = UriComponentsBuilder.fromUriString(authorizeRedirectedUrl)
                .build()
                .getPath();

        wm1.stubFor(com.github.tomakehurst.wiremock.client.WireMock.get(urlPathEqualTo(path))
                .willReturn(aResponse()
                        .withHeader("Location", """
                                https://localhost:8443/login/oauth2/code/test-oauth-provider?\
                                state=%s\
                                &code=dummy\
                                &scope=openid\
                                &authuser=0\
                                &prompt=none\
                                """.formatted(state))
                        .withStatus(302)));

        mockMvc.perform(get(authorizeRedirectedUrl)
                        .secure(true))
                .andExpect(status().is3xxRedirection())
                .andExpect(MockMvcResultMatchers.redirectedUrlPattern("**/persons"));
    }
}
