package com.example.demo.domain.auth.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    public Collection<? extends GrantedAuthority> authoritiesOf(User user) {
        return List.of(new SimpleGrantedAuthority(user.getRole().name()));
    }
}