package com.ndsolutions.secureapi.user.api;

import com.ndsolutions.secureapi.user.domain.User;
import com.ndsolutions.secureapi.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<User>> list() {
        return ResponseEntity.ok(userService.list());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<User> create(@RequestBody Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");
        return ResponseEntity.ok(userService.createUser(username, password));
    }
}
