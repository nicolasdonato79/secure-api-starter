package com.ndsolutions.secureapi.auth.service;

import com.ndsolutions.secureapi.security.JwtTokenService;
import com.ndsolutions.secureapi.security.model.AuthRequest;
import com.ndsolutions.secureapi.security.model.AuthResponse;
import com.ndsolutions.secureapi.user.persistence.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenService tokenService;
    private final JwtDecoder jwtDecoder;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       JwtTokenService tokenService,
                       JwtDecoder jwtDecoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.jwtDecoder = jwtDecoder;
    }

    public AuthResponse login(AuthRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String access = tokenService.createAccessToken(user);
        String refresh = tokenService.createRefreshToken(user);
        return new AuthResponse(access, refresh);
    }

    public AuthResponse refresh(String refreshToken) {
        Jwt jwt = jwtDecoder.decode(refreshToken);

        String typ = jwt.getClaimAsString("typ");
        if (!"refresh".equals(typ)) {
            throw new IllegalArgumentException("Invalid token type");
        }

        var user = userRepository.findByUsername(jwt.getSubject())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String access = tokenService.createAccessToken(user);
        String newRefresh = tokenService.createRefreshToken(user);
        return new AuthResponse(access, newRefresh);
    }
}
