package com.example.iam.web.logout;

import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Structural bounds only; Spring's OIDC provider still verifies signature and claims.
 * Converts malformed inputs to 400 and verifier outages to retryable 503 without leaking JWTs.
 */
@Component
@Order(-101)
public class LogoutRequestBoundary extends OncePerRequestFilter {
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/logout/connect/back-channel/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        response.setHeader("Cache-Control", "no-store");
        try {
            String[] values = request.getParameterValues("logout_token");
            if (!"POST".equals(request.getMethod()) || values == null || values.length != 1 || values[0].length() > 16000)
                throw new IllegalArgumentException();
            var jwt = SignedJWT.parse(values[0]);
            var claims = jwt.getJWTClaimsSet();
            var events = claims.getJSONObjectClaim("events");
            if (events == null || !(events.get("http://schemas.openid.net/event/backchannel-logout") instanceof java.util.Map<?, ?> event) || !event.isEmpty())
                throw new IllegalArgumentException();
            if (claims.getIssuer() == null || claims.getAudience().size() != 1 || claims.getIssueTime() == null || claims.getExpirationTime() == null
                    || claims.getJWTID() == null || claims.getStringClaim("sid") == null || claims.getClaims().containsKey("nonce"))
                throw new IllegalArgumentException();
        } catch (Exception e) {
            response.setStatus(400);
            return;
        }
        // This deployment invalidates JDBC sessions directly; never permit Spring's
        // private loopback selector to bypass that handler on an external request.
        var external = new HttpServletRequestWrapper(request) {
            @Override
            public String getParameter(String name) {
                return name.equals("_spring_security_internal_logout") ? null : super.getParameter(name);
            }

            @Override
            public String[] getParameterValues(String name) {
                return name.equals("_spring_security_internal_logout") ? null : super.getParameterValues(name);
            }

            @Override
            public java.util.Map<String, String[]> getParameterMap() {
                var parameters = new java.util.HashMap<>(super.getParameterMap());
                parameters.remove("_spring_security_internal_logout");
                return java.util.Collections.unmodifiableMap(parameters);
            }

            @Override
            public java.util.Enumeration<String> getParameterNames() {
                return java.util.Collections.enumeration(getParameterMap().keySet());
            }
        };
        try {
            chain.doFilter(external, response);
        } catch (org.springframework.security.authentication.AuthenticationServiceException e) {
            response.setStatus(503);
        }
    }
}
