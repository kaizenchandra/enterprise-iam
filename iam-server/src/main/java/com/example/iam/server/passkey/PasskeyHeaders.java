package com.example.iam.server.passkey;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@org.springframework.core.annotation.Order(-104)
public class PasskeyHeaders extends OncePerRequestFilter {
    @Override
    protected boolean shouldNotFilter(HttpServletRequest req) {
        return !(req.getRequestURI().startsWith("/passkeys") || req.getRequestURI().equals("/login"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        chain.doFilter(req, res);
    }
}
