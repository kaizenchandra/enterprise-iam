package com.example.iam.server.account;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@org.springframework.core.annotation.Order(-103)
public class AccountHeaders extends OncePerRequestFilter {
    @Override
    protected boolean shouldNotFilter(HttpServletRequest r) {
        return !r.getRequestURI().startsWith("/account");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("Referrer-Policy", "no-referrer");
        res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        chain.doFilter(req, res);
    }
}
