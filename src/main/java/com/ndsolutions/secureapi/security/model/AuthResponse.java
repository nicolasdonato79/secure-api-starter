package com.ndsolutions.secureapi.security.model;

public class AuthResponse {
    private final String accessToken;
    private final String refreshToken;
    private final String tokenType = "Bearer";

    public AuthResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public String getTokenType() { return tokenType; }
}
