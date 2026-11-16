package com.example.iam.server.identity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HomeController {
    @GetMapping("/")
    public Map<String, Object> home() {
        return Map.of("service", "Enterprise IAM", "authenticated", true);
    }
}
