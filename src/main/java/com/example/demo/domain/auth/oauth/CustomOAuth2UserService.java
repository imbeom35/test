package com.example.demo.domain.auth.oauth;

import com.example.demo.domain.auth.user.Role;
import com.example.demo.domain.auth.user.User;
import com.example.demo.domain.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest req) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(req);
        Map<String, Object> attrs = oAuth2User.getAttributes();
        String registrationId = req.getClientRegistration().getRegistrationId();

        // Provider 별 표준화 (Google 기준)
        String email = extractEmail(registrationId, attrs);
        String name  = extractName(registrationId, attrs);
        String providerId = extractProviderId(registrationId, attrs);

        if (email == null || email.isBlank()) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_email"), "Email not found from provider");
        }

        User user = userRepository.findByEmail(email)
                .map(u -> u.updateNameIfNeeded(name))
                .orElseGet(() -> userRepository.save(User.ofOauth(email, name, registrationId, providerId, Role.ROLE_USER)));

        return new CustomOAuth2User(
                user.getId(),
                user.getEmail(),
                List.of(new SimpleGrantedAuthority(user.getRole().name())),
                attrs
        );
    }

    private String extractEmail(String registrationId, Map<String, Object> attrs) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return (String) attrs.get("email");
        }
        return (String) attrs.get("email");
    }

    private String extractName(String registrationId, Map<String, Object> attrs) {
        if ("google".equalsIgnoreCase(registrationId)) {
            Object name = attrs.get("name");
            if (name == null) name = attrs.get("given_name");
            return name == null ? "" : name.toString();
        }
        return (String) attrs.getOrDefault("name", "");
    }

    private String extractProviderId(String registrationId, Map<String, Object> attrs) {
        if ("google".equalsIgnoreCase(registrationId)) {
            return (String) attrs.get("sub");
        }
        return (String) attrs.getOrDefault("id", "");
    }
}