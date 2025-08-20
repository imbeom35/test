package com.example.demo.domain.auth.token;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    boolean existsByUserIdAndToken(Long userId, String token);
    void deleteByUserId(Long userId);
}