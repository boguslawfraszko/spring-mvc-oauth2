package com.example.spring.security.oauth2.config;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.apache.http.client.utils.URIBuilder;
import org.jetbrains.annotations.NotNull;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Import({SecurityConfig.class, TestClientConfig.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class SecurityConfigE2ETestKeyClock {

    private static KeycloakContainer keycloak;

    static {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:22.0")
                .withRealmImportFile("realm-test-spring.json")
                .withDisabledCaching()
                .withEnabledMetrics()
                .withReuse(false);

        keycloak.start();
    }

    @Autowired @Qualifier("testNoCertVerificationRestTemplate")
    private RestTemplate restTemplate;

    @DynamicPropertySource
    static void updateKeycloakConfiguration(DynamicPropertyRegistry registry) {
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

        var redirectToKeyCloakResult = restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/keycloak", String.class);
        var keyCloakLoginPage = redirectToKeyCloakResult.getHeaders().get("Location").get(0);

        var jsesionid = getJsesionid(redirectToKeyCloakResult);

        var loadKeyCloackLoginPageResult = restTemplate.getForEntity(keyCloakLoginPage, String.class);

        var actionUrl = getLoginUrl(loadKeyCloackLoginPageResult);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.put("username", Collections.singletonList("test"));
        formData.put("password", Collections.singletonList("wrong"));

        var keyCloakLoginResult = restTemplate.postForEntity(actionUrl, formData, String.class);


        Assertions.assertTrue(keyCloakLoginResult.getStatusCode().is2xxSuccessful());
        Assertions.assertTrue(keyCloakLoginResult.getBody().contains("Invalid username or password"));
    }

    @Test
    @DisplayName("Should login to oauth2 provider")
    public void testShouldLoginToOAuthProvider(){

        var redirectToKeyCloakResult = restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/keycloak", String.class);
        var keyCloakLoginPage = redirectToKeyCloakResult.getHeaders().get("Location").get(0);

        var loadKeyCloackLoginPageResult = restTemplate.getForEntity(keyCloakLoginPage, String.class);

        var actionUrl = getLoginUrl(loadKeyCloackLoginPageResult);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.put("username", Collections.singletonList("test"));
        formData.put("password", Collections.singletonList("test"));

        var keyCloakLoginResult = restTemplate.postForEntity(actionUrl, formData, String.class);

        Assertions.assertTrue(keyCloakLoginResult.getStatusCode().is3xxRedirection());

        var keyCloakLoginRedirect = keyCloakLoginResult.getHeaders().get("Location").get(0);
        Assertions.assertTrue(keyCloakLoginRedirect.contains("https://localhost:8443/login/oauth2/code/keycloak"));

    }


    @Test
    @DisplayName("Should accept authorization code and redirect to main page")
    public void testShouldAcceptAuthorizationCodeAndRedirectToMainPage(){

        var redirectToKeyCloakResult = restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/keycloak", String.class);
        var keyCloakLoginPage = redirectToKeyCloakResult.getHeaders().get("Location").get(0);

        var jsesionid = getJsesionid(redirectToKeyCloakResult);

        var loadKeyCloackLoginPageResult = restTemplate.getForEntity(keyCloakLoginPage, String.class);

        var actionUrl = getLoginUrl(loadKeyCloackLoginPageResult);

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.put("username", Collections.singletonList("test"));
        formData.put("password", Collections.singletonList("test"));

        var keyCloakLoginResult = restTemplate.postForEntity(actionUrl, formData, String.class);

        Assertions.assertTrue(keyCloakLoginResult.getStatusCode().is3xxRedirection());

        var keyCloakLoginRedirect = keyCloakLoginResult.getHeaders().get("Location").get(0);
        Assertions.assertTrue(keyCloakLoginRedirect.contains("https://localhost:8443/login/oauth2/code/keycloak"));

        HttpEntity<String> entity = getHttpEntityWithJession(jsesionid);
        keyCloakLoginRedirect = fixEncoding(keyCloakLoginRedirect);

        var loginWithAuthorizationCodeResult = restTemplate.getForEntity(keyCloakLoginRedirect, String.class, entity);
        Assertions.assertTrue(loginWithAuthorizationCodeResult.getStatusCode().is3xxRedirection());

        var redirectToHomePage = loginWithAuthorizationCodeResult.getHeaders().get("Location").get(0);
        Assertions.assertTrue(redirectToHomePage.contains("https://localhost:8443/persons"));

        var homePageResult = restTemplate.getForEntity(redirectToHomePage, String.class);
        Assertions.assertTrue(homePageResult.getStatusCode().is2xxSuccessful());

    }

    @NotNull
    private static String fixEncoding(String keyCloakLoginRedirect) {
        return keyCloakLoginRedirect.replace("%253D", "=");
    }

    @NotNull
    private static HttpEntity<String> getHttpEntityWithJession(String jsesionid) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", "JSESSIONID=" + jsesionid);
        HttpEntity<String> entity = new HttpEntity<>(headers);
        return entity;
    }

    @NotNull
    private static String getLoginUrl(ResponseEntity<String> loadKeyCloackLoginPageResult) {
        Document doc = Jsoup.parse(loadKeyCloackLoginPageResult.getBody());
        Element form = doc.select("form").first();
        String actionUrl = form.attr("action");
        return actionUrl;
    }

    private static String getJsesionid(ResponseEntity<String> result) {
        String jsesionid = null;
        Matcher matcher = Pattern.compile("JSESSIONID=(\\w+);")
                .matcher(result.getHeaders().get("Set-Cookie").get(0));
        if (matcher.find()) {
            jsesionid = matcher.group(1);
        }
        return jsesionid;
    }


}
