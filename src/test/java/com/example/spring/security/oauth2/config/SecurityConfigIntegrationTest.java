package com.example.spring.security.oauth2.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@ExtendWith(SpringExtension.class)
@WebMvcTest
@Import(SecurityConfig.class)
public class SecurityConfigIntegrationTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {

        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .alwaysDo(print())
                .build();
    }

    @Test
    @DisplayName("Test filter chain when requesting a protected page, then redirect to the login page")
    public void testFilterChainWhenRequestToProtectedPageThenRedirectToLoginPage() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/persons").secure(true))
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("Test filter chain when requesting the login page, then return the login page")
    public void testFilterChainWhenRequestToLoginPageThenReturnLoginPage() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/login").secure(true))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }
    @Test
    @DisplayName("Test filter chain when requesting the logout page, then redirect to the default success URL")
    public void testFilterChainWhenRequestToLogoutPageThenRedirectToDefaultSuccessUrl() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/logout").secure(true))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andExpect(MockMvcResultMatchers.redirectedUrlPattern("/login?logout"));
    }
}
