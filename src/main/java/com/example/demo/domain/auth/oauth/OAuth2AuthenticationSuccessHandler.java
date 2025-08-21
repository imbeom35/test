package com.example.demo.domain.auth.oauth;

import com.example.demo.domain.auth.cookie.HttpCookieOAuth2AuthorizationRequestRepository;
import com.example.demo.domain.auth.jwt.JwtTokenProvider;
import com.example.demo.domain.auth.token.TokenService;
import com.example.demo.domain.auth.cookie.CookieUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest req,
                                        HttpServletResponse res,
                                        Authentication authentication)
            throws IOException, ServletException {
        CustomOAuth2User user = (CustomOAuth2User) authentication.getPrincipal();

        String access = tokenProvider.createAccessToken(user.getUserId(), user.getAuthorities());
        String refresh = tokenProvider.createRefreshToken(user.getUserId());
        tokenService.storeRefresh(user.getUserId(), refresh);

        // HttpOnly 쿠키 저장
        CookieUtils.addHttpOnlyCookie(res, "access_token", access, 15 * 60);
        CookieUtils.addHttpOnlyCookie(res, "refresh_token", refresh, 14 * 24 * 60 * 60);

        String target = CookieUtils.getCookie(req, HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue)
                .orElse("http://localhost:5173");

        // 불필요 쿠키 정리
        HttpCookieOAuth2AuthorizationRequestRepository.clearAuthorizationRequestCookies(req, res);

        getRedirectStrategy().sendRedirect(req, res, target);
    }
}