package com.ndsolutions.secureapi.auth.api.me;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class DebugAuthController {

    @GetMapping("/api/me")
    public Map<String, Object> me(Authentication auth) {
        return Map.of(
                "name", auth.getName(),
                "type", auth.getClass().getSimpleName(),
                "authorities", auth.getAuthorities().stream().map(a -> a.getAuthority()).toList(),
                "details", auth.getDetails()
        );
    }
}
