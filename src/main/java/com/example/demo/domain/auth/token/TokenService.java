package com.example.demo.domain.auth.token;

import com.example.demo.domain.auth.jwt.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public String reissueAccess(String refreshToken) {
        Claims claims = tokenProvider.parse(refreshToken).getPayload();
        if (!"refresh".equals(claims.get("typ"))) throw new JwtException("not a refresh token");
        Long userId = Long.valueOf(claims.getSubject());
        if (!refreshTokenRepository.existsByUserIdAndToken(userId, refreshToken))
            throw new JwtException("refresh not found");

        // 최소 권한: USER. 필요 시 DB 조회 후 적절히 구성
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        return tokenProvider.createAccessToken(userId, authorities);
    }

    public void revoke(Long userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }

    public void storeRefresh(Long userId, String token) {
        refreshTokenRepository.save(RefreshToken.of(userId, token));
    }
}