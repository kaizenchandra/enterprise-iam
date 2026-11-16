package com.example.iam.server.account;

import com.example.iam.server.security.AuthUi;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

/**
 * OAuth browser navigation redirects to the frontend; no backend-rendered login view.
 */
@RestController
public class LoginPage {
    private final AuthUi ui;

    public LoginPage(AuthUi ui) {
        this.ui = ui;
    }

    @GetMapping("/login")
    public ResponseEntity<Void> login() {
        return ResponseEntity.status(302).location(URI.create(ui.page("/auth/login"))).build();
    }
}
