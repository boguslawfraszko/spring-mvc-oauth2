package com.example.spring.security.springmvcoauth2.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest
@AutoConfigureMockMvc
public class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Test filter chain when requesting the login page, then return the login page")
    public void testFilterChainWhenRequestToLoginPageThenReturnLoginPage() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/login"))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    @DisplayName("Test filter chain when requesting the logout page, then redirect to the default success URL")
    public void testFilterChainWhenRequestToLogoutPageThenRedirectToDefaultSuccessUrl() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/logout"))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andExpect(MockMvcResultMatchers.redirectedUrlPattern("**/login"));
    }

    @Test
    @DisplayName("Test filter chain when requesting a protected page, then redirect to the login page")
    public void testFilterChainWhenRequestToProtectedPageThenRedirectToLoginPage() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.get("/protected"))
                .andExpect(MockMvcResultMatchers.status().isFound())
                .andExpect(MockMvcResultMatchers.redirectedUrlPattern("**/login?logout"));
    }

    @Test
    @DisplayName("Test filter chain when making a POST request without a CSRF token, then return forbidden")
    public void testFilterChainWhenPostRequestWithoutCsrfTokenThenReturnForbidden() throws Exception {
        mockMvc.perform(MockMvcRequestBuilders.post("/protected"))
                .andExpect(MockMvcResultMatchers.status().isForbidden());
    }
}
