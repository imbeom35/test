package com.example.demo.domain.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final JwtProperties props;
    private Key key;

    @PostConstruct
    void init() {
        byte[] keyBytes = io.jsonwebtoken.io.Decoders.BASE64.decode(props.getSecret());
        if (keyBytes.length < 32) throw new IllegalArgumentException("JWT secret must be >= 256 bits");
        this.key = io.jsonwebtoken.security.Keys.hmacShaKeyFor(keyBytes);
    }

    public String createAccessToken(Long userId, Collection<? extends GrantedAuthority> authorities) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))                                    // setSubject -> subject
                .claim("auth", authorities.stream().map(GrantedAuthority::getAuthority).toList())
                .issuedAt(Date.from(now))                                           // setIssuedAt -> issuedAt
                .expiration(Date.from(now.plusMillis(props.getAccessTokenValidityMs()))) // setExpiration -> expiration
                .signWith(key)                                                      // 알고리즘은 key로부터 자동 추론(HS256)
                .compact();
    }

    public String createRefreshToken(Long userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("typ", "refresh")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(props.getRefreshTokenValidityMs())))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token);
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parse(token).getPayload();
        String userId = claims.getSubject();
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("auth");
        Collection<? extends GrantedAuthority> authorities =
                roles == null ? List.of() : roles.stream().map(SimpleGrantedAuthority::new).toList();
        UserDetails principal = org.springframework.security.core.userdetails.User
                .withUsername(userId).password("N/A").authorities(authorities).build();
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }
}