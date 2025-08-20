package com.example.demo.domain.auth.controller;

import com.example.demo.domain.auth.token.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(value = "refresh_token", required = false) String refreshFromCookie,
                                     @RequestHeader(value = AUTHORIZATION, required = false) String authHeader) {
        String refresh = refreshFromCookie;
        if (refresh == null && authHeader != null && authHeader.startsWith("Bearer ")) {
            refresh = authHeader.substring(7);
        }
        if (refresh == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No refresh token");

        String newAccess = tokenService.reissueAccess(refresh);
        return ResponseEntity.ok().body(newAccess);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Authentication auth, HttpServletResponse res) {
        if (auth != null) {
            Long userId = Long.valueOf(auth.getName());
            tokenService.revoke(userId);
        }
        // 클라이언트 쿠키 제거 힌트(실제 삭제는 클라 도메인/경로 동일 조건 필요)
        Cookie access = new Cookie("access_token", "");
        access.setPath("/");
        access.setMaxAge(0);
        access.setHttpOnly(true);
        res.addCookie(access);

        Cookie refresh = new Cookie("refresh_token", "");
        refresh.setPath("/");
        refresh.setMaxAge(0);
        refresh.setHttpOnly(true);
        res.addCookie(refresh);

        return ResponseEntity.ok().build();
    }
}