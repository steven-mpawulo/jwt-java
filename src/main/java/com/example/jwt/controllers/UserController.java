package com.example.jwt.controllers;

import com.example.jwt.config.JwtService;
import com.example.jwt.models.Role;
import com.example.jwt.models.User;
import com.example.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1")
public class UserController {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    private Map<String, Object> response = new HashMap<>();
    @PostMapping("/auth/signup")
    public ResponseEntity<Map<String, Object>> signUp (@RequestBody Map<String, Object> jsonData) {
        String password = (String)jsonData.get("password");
        String hashedPassword = passwordEncoder.encode(password);
        String userRole = (String) jsonData.get("role");
         boolean isAdmin = "ADMIN".equals(userRole);
        User user = new User(
                (String)jsonData.get("firstName"),
                (String)jsonData.get("lastName"),
                (String)jsonData.get("email"),
                hashedPassword,
                isAdmin ? Role.ADMIN : Role.USER


        );
        User savedUser = userRepository.save(user);
        Map<String, Object> claims = new HashMap<>();
        claims.put("id",savedUser.getId());
        String token = jwtService.generateToken(savedUser, claims);
        response.put("token", token);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/auth/signin")
    public ResponseEntity<Map<String, Object>> signIn(@RequestBody Map<String, Object> jsonData) {
        String email = (String) jsonData.get("email");
        String password = (String) jsonData.get("password");
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        User user = (User) authentication.getPrincipal();
        Optional<User> userFromDatabase = userRepository.findByEmail(user.getUsername());
        if (userFromDatabase.isPresent()) {
            User actualUser = userFromDatabase.get();
            Map<String, Object> claims = new HashMap<>();
            claims.put("id", actualUser.getId());
            String token = jwtService.generateToken(actualUser, claims);
            Map<String, Object> response = new HashMap<>();
            response.put("token", token);

            return new ResponseEntity<>(response, HttpStatus.OK);
        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No user found");
        }
    }

    @GetMapping("/home")
    public String home() {
        return "am home";
    }
}
