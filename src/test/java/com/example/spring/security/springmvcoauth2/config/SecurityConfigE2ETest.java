package com.example.spring.security.springmvcoauth2.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.http.Body;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Import;
import org.springframework.http.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import({SecurityConfig.class, TestClientConfig.class})
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class SecurityConfigE2ETest {
    private final static int EXPECTED_PORT = 7777;

    private MockMvc mockMvc;

    @Autowired @Qualifier("testNoCertVerificationRestTemplate")
    RestTemplate restTemplate;

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private TestRestTemplate template;

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
    @DisplayName("Should redirect to OAuth authorize url and with return url containing nonce ")
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
    @DisplayName("Should login on mock oauth provider ")
    public void testOAuthLogin() throws Exception {

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

        var response = restTemplate.getForEntity(authorizeRedirectedUrl, String.class);

        Assertions.assertEquals(response.getStatusCode(), HttpStatus.FOUND);
        String locationHeader = response.getHeaders().get("Location").get(0);
        Assertions.assertTrue(locationHeader.contains(state));
        Assertions.assertTrue(locationHeader.contains("https://localhost:8443/login/oauth2/code/test-oauth-provider"));

        WireMock.verify(exactly(1), getRequestedFor(urlPathTemplate(path)));
    }

    @Test
    @DisplayName("Should reject redirect from mock auth provider without code ")
    public void testReturnFromMockOAuthProviderWithoutCode() throws Exception {

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

        var response = restTemplate.getForEntity(authorizeRedirectedUrl, String.class);

        mockMvc.perform(get(response.getHeaders().get("Location").get(0)).secure(true))
                .andExpect(status().is3xxRedirection())
                .andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login?error"));

    }


    @Test
    @DisplayName("Should accept redirect from mock auth provider ")
    public void testReturnFromMockOAuthProvider() {

        var authorizationRedirectResponse = this.restTemplate.getForEntity("https://localhost:8443/oauth2/authorization/test-oauth-provider", String.class);

        String jsessionId = getJsessionId(authorizationRedirectResponse);
        String authorizeRedirectedUrl = authorizationRedirectResponse.getHeaders().get("Location").get(0);

        String state = UriComponentsBuilder.fromUriString(authorizeRedirectedUrl)
                .build()
                .getQueryParams()
                .getFirst("state")
                .replaceAll("%3D", "=");

        String path = UriComponentsBuilder.fromUriString(authorizeRedirectedUrl)
                .build()
                .getPath();

        wireMocks(state, path);

        var authorizationResponse = restTemplate.getForEntity(authorizeRedirectedUrl, String.class);

        WireMock.verify(exactly(1), getRequestedFor(urlPathTemplate(path)));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("JSESSIONID", jsessionId);
        HttpEntity request = new HttpEntity(headers);

        var fresponse = this.restTemplate.getForEntity(authorizationResponse.getHeaders().get("Location").get(0), String.class, request);

        Assertions.assertTrue(fresponse.getStatusCode().is3xxRedirection());

        Assertions.assertEquals(fresponse.getHeaders().get("Location").get(0), "https://localhost:8443/persons");

        WireMock.verify(1, postRequestedFor(urlPathTemplate("https://localhost:8089/oauth/token")));

    }

    private void wireMocks(String state, String path) {
        wm1.stubFor(WireMock.get(urlPathEqualTo(path))
                .willReturn(aResponse()
                        .withHeader("Location", """
                                https://localhost:8443/login/oauth2/code/test-oauth-provider?\
                                state=%s\
                                &code=123\
                                &scope=openid\
                                &authuser=0\
                                &prompt=none\
                                """.formatted(state))
                        .withStatus(302)));

        wm1.stubFor(WireMock.post(urlPathEqualTo("https://localhost:8089/oauth/token"))
                .willReturn(aResponse()
                        .withResponseBody(Body.fromOneOf(null,null,null,
                                Base64.getEncoder().encodeToString(generateJwt().getBytes())))
                        .withStatus(200)));
    }

    private static String getJsessionId(ResponseEntity<String> authorizationResponse) {
        var jsessionCookie = authorizationResponse.getHeaders().get("Set-Cookie").get(0);
        Pattern pattern = Pattern.compile("JSESSIONID=([^;]+)");
        Matcher matcher = pattern.matcher(jsessionCookie);

        Assertions.assertTrue(matcher.find());
        String jsessionId = matcher.group(1);
        return jsessionId;
    }

    private String generateJwt() {
        Algorithm algorithm = Algorithm.HMAC256("X");
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("X")
                .build();

        return JWT.create()
                .withIssuer("X")
                .withSubject("John Smith")
                .withClaim("userId", "1234")
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 5000L))
                .withJWTId(UUID.randomUUID()
                        .toString())
                .withNotBefore(new Date(System.currentTimeMillis() + 1000L))
                .sign(algorithm);

    }
}
