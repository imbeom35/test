package com.example.demo.domain.auth.user;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class User {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false, unique = true, length = 255)
    private String email;

    @Column(nullable=false, length = 100)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false, length = 20)
    private Role role;

    @Column(length = 50)
    private String provider;    // e.g., google/naver/kakao

    @Column(length = 100)
    private String providerId;  // sub/id

    public static User ofOauth(String email, String name, String provider, String providerId, Role role) {
        return User.builder()
                .email(email)
                .name(name == null ? "" : name)
                .provider(provider)
                .providerId(providerId)
                .role(role)
                .build();
    }

    public User updateNameIfNeeded(String newName) {
        if (newName != null && !newName.isBlank() && !newName.equals(this.name)) {
            this.name = newName;
        }
        return this;
    }
}