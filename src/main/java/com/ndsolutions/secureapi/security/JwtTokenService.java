package com.ndsolutions.secureapi.security;

import com.ndsolutions.secureapi.user.domain.Role;
import com.ndsolutions.secureapi.user.domain.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtTokenService {

    private final JwtEncoder jwtEncoder;
    private final String issuer;
    private final String audience;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;

    public JwtTokenService(
            JwtEncoder jwtEncoder,
            @Value("${app.security.issuer}") String issuer,
            @Value("${app.security.audience}") String audience,
            @Value("${app.security.accessTtlSeconds}") long accessTtlSeconds,
            @Value("${app.security.refreshTtlSeconds}") long refreshTtlSeconds
    ) {
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
        this.audience = audience;
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
    }

    public String createAccessToken(User user) {
        return encode(user, accessTtlSeconds, "access");
    }

    public String createRefreshToken(User user) {
        return encode(user, refreshTtlSeconds, "refresh");
    }

    private String encode(User user, long ttlSeconds, String type) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles().stream().map(Role::getName).toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(ttlSeconds))
                .subject(user.getUsername())
                .id(UUID.randomUUID().toString())
                .claim("typ", type)
                .claim("roles", roles)
                .build();

        // Forzamos RS512
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS512)
                .type("JWT")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
