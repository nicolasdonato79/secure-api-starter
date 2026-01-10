package com.ndsolutions.secureapi.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;

@Component
public class RsaKeyProvider {

    private final String privatePemB64;
    private final String publicPemB64;

    public RsaKeyProvider(
            @Value("${app.security.privateKeyPemB64:}") String privatePemB64,
            @Value("${app.security.publicKeyPemB64:}") String publicPemB64
    ) {
        this.privatePemB64 = privatePemB64 == null ? "" : privatePemB64.trim();
        this.publicPemB64 = publicPemB64 == null ? "" : publicPemB64.trim();
    }

    public KeyMaterial loadOrGenerate() {
        if (!privatePemB64.isBlank() && !publicPemB64.isBlank()) {
            RSAPrivateKey priv = readPrivateKeyFromPemB64(privatePemB64);
            RSAPublicKey pub = readPublicKeyFromPemB64(publicPemB64);
            return new KeyMaterial(pub, priv);
        }
        // DEV fallback: keys efímeras (para demo local)
        return generateEphemeral();
    }

    private KeyMaterial generateEphemeral() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            return new KeyMaterial((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA keypair", e);
        }
    }

    private static RSAPublicKey readPublicKeyFromPemB64(String pemB64) {
        try {
            String pem = new String(Base64.getDecoder().decode(pemB64), StandardCharsets.UTF_8);
            String cleaned = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(cleaned);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid public key PEM (B64)", e);
        }
    }

    private static RSAPrivateKey readPrivateKeyFromPemB64(String pemB64) {
        try {
            String pem = new String(Base64.getDecoder().decode(pemB64), StandardCharsets.UTF_8);
            String cleaned = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(cleaned);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid private key PEM (B64)", e);
        }
    }
}
