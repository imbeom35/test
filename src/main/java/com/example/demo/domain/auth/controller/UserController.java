package com.example.demo.domain.auth.controller;

import com.example.demo.domain.auth.user.User;
import com.example.demo.domain.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/me")
    public ResponseEntity<?> me(Authentication auth) {
        if (auth == null) return ResponseEntity.status(401).body("unauthorized");
        Long userId = Long.valueOf(auth.getName()); // CustomOAuth2User.getName() or Jwt subject
        User user = userRepository.findById(userId).orElse(null);
        if (user == null) return ResponseEntity.status(404).body("user not found");
        return ResponseEntity.ok(new MeDto(user.getId(), user.getEmail(), user.getRole().name(), user.getProvider()));
    }

    private record MeDto(Long id, String email, String role, String provider) {}
}