package com.example.demo.domain.auth.oauth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest req,
                                        HttpServletResponse res,
                                        AuthenticationException ex)
            throws IOException, ServletException {
        String target = "http://localhost:5173/login?error=" +
                URLEncoder.encode(ex.getMessage(), StandardCharsets.UTF_8);
        getRedirectStrategy().sendRedirect(req, res, target);
    }
}