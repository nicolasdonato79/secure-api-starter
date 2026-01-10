package com.ndsolutions.secureapi.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public record KeyMaterial(RSAPublicKey publicKey, RSAPrivateKey privateKey) {}
