package com.ndsolutions.secureapi.user.service;

import com.ndsolutions.secureapi.user.domain.Role;
import com.ndsolutions.secureapi.user.domain.User;
import com.ndsolutions.secureapi.user.persistence.RoleRepository;
import com.ndsolutions.secureapi.user.persistence.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public List<User> list() {
        return userRepository.findAll();
    }

    @Transactional
    public User createAdminIfMissing(String username, String rawPassword) {
        return userRepository.findByUsername(username).orElseGet(() -> {
            Role admin = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN missing (Flyway seed not applied?)"));

            User u = new User();
            u.setUsername(username);
            u.setPasswordHash(passwordEncoder.encode(rawPassword));
            u.getRoles().add(admin);
            return userRepository.save(u);
        });
    }

    @Transactional
    public User createUser(String username, String rawPassword) {
        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("username already exists");
        }
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER missing"));
        User u = new User();
        u.setUsername(username);
        u.setPasswordHash(passwordEncoder.encode(rawPassword));
        u.getRoles().add(userRole);
        return userRepository.save(u);
    }
}
