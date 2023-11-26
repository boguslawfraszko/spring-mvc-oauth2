package com.example.spring.security.springmvcoauth2.config;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.client.utils.URIBuilder;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import({SecurityConfig.class, TestClientConfig.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class SecurityConfigE2ETestKeyClock {

    private static KeycloakContainer keycloak;

    static {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:22.0"
        ).withRealmImportFile("realm-test-spring.json");
        keycloak.start();
    }

    private MockMvc mockMvc;
    @Autowired
    private WebApplicationContext context;

    @Autowired @Qualifier("testNoCertVerificationRestTemplate")
    private RestTemplate restTemplate;

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.provider.keycloak.issuer-uri",
                () -> keycloak.getAuthServerUrl() + "/realms/test-spring-realm");
        registry.add("spring.security.oauth2.client.provider.keycloak.token-uri",
                () -> keycloak.getAuthServerUrl() + "/realms/test-spring/protocol/openid-connect/token");
        registry.add("spring.security.oauth2.client.provider.keycloak.authorization-uri",
                () -> keycloak.getAuthServerUrl() + "/realms/test-spring/protocol/openid-connect/auth");
        registry.add("spring.security.oauth2.client.provider.keycloak.user-info-uri",
                () -> keycloak.getAuthServerUrl() + "/realms/test-spring/protocol/openid-connect/userinfo");
        registry.add("spring.security.oauth2.client.provider.keycloak.jwk-set-uri",
                () -> keycloak.getAuthServerUrl() + "/realms/test-spring/protocol/openid-connect/certs");
    }



    @BeforeEach
    public void setup() {

        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .alwaysDo(print())
                .build();
    }

    @Test
    @DisplayName("Should generate token for password grant type ")
    public void testReturnTokenForPasswordGrantType() throws Exception {

        URI authorizationURI = new URIBuilder(keycloak.getAuthServerUrl() + "/realms/test-spring/protocol/openid-connect/token").build();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.put("grant_type", Collections.singletonList("password"));
        formData.put("client_id", Collections.singletonList("test-spring-client"));
        formData.put("username", Collections.singletonList("test"));
        formData.put("password", Collections.singletonList("test"));

        RestTemplate client = new RestTemplateBuilder()
                .build();

        var result = client.postForEntity(authorizationURI, formData, String.class);

        Assertions.assertTrue(result.getStatusCode().is2xxSuccessful());

    }

    @Test
    @DisplayName("Should redirect to login page")
    public void testRedirectToLoginPage(){

        var result = restTemplate.getForEntity("https://localhost:8443/persons", String.class);
        var redirect = result.getHeaders().get("Location").get(0);


        Assertions.assertEquals(redirect, "https://localhost:8443/login");

        result = restTemplate.getForEntity(redirect, String.class);

        Assertions.assertTrue(result.getStatusCode().is2xxSuccessful());
        Assertions.assertTrue(result.getBody().contains("/oauth2/authorization/keycloak"));

    }


    @Test
    @DisplayName("Should redirect to oauth2 provider")
    public void testShouldRedirectToAuthProvider(){

        var result = restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/keycloak", String.class);
        var redirect = result.getHeaders().get("Location").get(0);

        result = restTemplate.getForEntity(redirect, String.class);

        Assertions.assertTrue(result.getStatusCode().is2xxSuccessful());
        Assertions.assertTrue(result.getBody().contains("Sign in to your account"));

    }

    @Test
    @DisplayName("Should not login to oauth2 provider with wrong password")
    public void testShouldNotLoginToOAuthProviderWithWrongPassword(){

        var result = restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/keycloak", String.class);
        var redirect = result.getHeaders().get("Location").get(0);

        result = restTemplate.getForEntity(redirect, String.class);

        Document doc = Jsoup.parse(result.getBody());
        Element form = doc.select("form").first();
        String actionUrl = form.attr("action");


        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.put("username", Collections.singletonList("test"));
        formData.put("password", Collections.singletonList("wrong"));

        result = restTemplate.postForEntity(actionUrl, "", String.class);

        Assertions.assertTrue(result.getStatusCode().is2xxSuccessful());
        Assertions.assertTrue(result.getBody().contains("Invalid username or password"));
    }

    @Test
    @DisplayName("Should login to oauth2 provider")
    public void testShouldLoginToOAuthProvider(){

        var result = restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/keycloak", String.class);
        var redirect = result.getHeaders().get("Location").get(0);

        result = restTemplate.getForEntity(redirect, String.class);

        Document doc = Jsoup.parse(result.getBody());
        Element form = doc.select("form").first();
        String actionUrl = form.attr("action");


        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.put("username", Collections.singletonList("test"));
        formData.put("password", Collections.singletonList("test"));

        result = restTemplate.postForEntity(actionUrl, "", String.class);

        Assertions.assertTrue(result.getStatusCode().is3xxRedirection());
    }


}
