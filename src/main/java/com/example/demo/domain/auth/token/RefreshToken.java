package com.example.demo.domain.auth.token;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    private Long userId; // 사용자 당 1개 refresh 정책(필요 시 복합키/다중 발급으로 변경)

    @Column(nullable = false, length = 2048)
    private String token;

    public static RefreshToken of(Long userId, String token) {
        return RefreshToken.builder().userId(userId).token(token).build();
    }

    public RefreshToken rotate(String newToken) {
        this.token = newToken;
        return this;
    }
}