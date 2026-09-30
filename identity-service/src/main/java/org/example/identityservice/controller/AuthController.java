package org.example.identityservice.controller;

import lombok.RequiredArgsConstructor;
import org.example.identityservice.models.dto.req.LoginReq;
import org.example.identityservice.models.dto.req.RegisterReq;
import org.example.identityservice.models.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterReq req) {
        authService.register(req);
        return ResponseEntity.status(HttpStatus.CREATED).body("Register Successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginReq req) {
        return ResponseEntity.ok(authService.login(req));
    }

}