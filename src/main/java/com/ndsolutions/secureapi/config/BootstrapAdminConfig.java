package com.ndsolutions.secureapi.config;

import com.ndsolutions.secureapi.user.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;



@Configuration
public class BootstrapAdminConfig {

    @Bean
    CommandLineRunner bootstrapAdmin(UserService userService) {
        return args -> {
            // El UserService ya implementa la lógica de creación si no existe
            userService.createAdminIfMissing("admin", "Nico1933");
        };
    }
}
