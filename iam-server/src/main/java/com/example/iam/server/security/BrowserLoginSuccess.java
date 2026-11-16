package com.example.iam.server.security;

import com.example.iam.server.account.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class BrowserLoginSuccess {
    private final RegistrationService navigation;
    private final JdbcTemplate db;

    public BrowserLoginSuccess(RegistrationService navigation, JdbcTemplate db) {
        this.navigation = navigation;
        this.db = db;
    }

    public String defaultTarget(Authentication authentication) {
        String target = navigation.consoleEntry();
        if (target.equals("/")) return target;
        boolean admin = Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from platform_administrators where user_id=?)", Boolean.class, authentication.getName()));
        return target + "?lane=" + (admin ? "admin" : "app");
    }

    public String destination(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        var cache = new org.springframework.security.web.savedrequest.HttpSessionRequestCache();
        var saved = cache.getRequest(request, response);
        if (saved != null) {
            cache.removeRequest(request, response);
            var uri = java.net.URI.create(saved.getRedirectUrl());
            if ("/oauth2/authorize".equals(uri.getRawPath())) return saved.getRedirectUrl();
        }
        return defaultTarget(authentication);
    }

    public void success(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws java.io.IOException, jakarta.servlet.ServletException {
        var handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl(defaultTarget(authentication));
        handler.onAuthenticationSuccess(request, response, authentication);
    }
}
