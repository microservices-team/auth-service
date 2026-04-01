package com.diegoanyosa.authservice.controller;

import com.diegoanyosa.authservice.dto.request.LoginRequest;
import com.diegoanyosa.authservice.dto.response.AuthResponse;
import com.diegoanyosa.authservice.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @MockBean  AuthService authService;

    @Test
    @DisplayName("POST /api/auth/login returns 200 with tokens")
    void login_ValidRequest_Returns200() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setEmail("diego@diegoanyosa.com");
        req.setPassword("password123");

        AuthResponse authResponse = AuthResponse.builder()
            .accessToken("jwt-token")
            .refreshToken("refresh-token")
            .tokenType("Bearer")
            .expiresIn(3600L)
            .email("diego@diegoanyosa.com")
            .name("Diego Anyosa")
            .roles(Set.of("USER"))
            .build();

        when(authService.login(any())).thenReturn(authResponse);

        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.accessToken").value("jwt-token"))
            .andExpect(jsonPath("$.data.email").value("diego@diegoanyosa.com"));
    }

    @Test
    @DisplayName("POST /api/auth/login returns 400 on invalid email")
    void login_InvalidEmail_Returns400() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setEmail("not-an-email");
        req.setPassword("password");

        mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
            .andExpect(status().isBadRequest());
    }
}
