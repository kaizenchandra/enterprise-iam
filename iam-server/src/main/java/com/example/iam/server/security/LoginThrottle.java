package com.example.iam.server.security;

import com.example.iam.server.token.TrackedAuthorizationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@org.springframework.core.annotation.Order(-101)
public class LoginThrottle extends OncePerRequestFilter {
    private static final DefaultRedisScript<Long> INCREMENT = new DefaultRedisScript<>("local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],60) end;return n", Long.class);
    private final StringRedisTemplate redis;

    public LoginThrottle(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest r) {
        return !"POST".equals(r.getMethod()) || !(r.getRequestURI().equals("/login") || r.getRequestURI().equals("/session/login") || r.getRequestURI().startsWith("/mfa/") || r.getRequestURI().startsWith("/account/") || r.getRequestURI().startsWith("/passkeys/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
        try {
            String ip = TrackedAuthorizationService.digest(req.getRemoteAddr());
            if (req.getRequestURI().equals("/account/register")) {
                Long registrations = redis.execute(INCREMENT, List.of("iam:throttle:registration:" + ip));
                if (registrations == null || registrations > 5) {
                    res.setHeader("Retry-After", "60");
                    res.sendError(429);
                    return;
                }
            }
            String user = TrackedAuthorizationService.digest(String.valueOf(req.getParameter("username")));
            String bucket = req.getRequestURI().startsWith("/passkeys/") ? "passkey" : req.getRequestURI().startsWith("/account/") ? "account" : req.getRequestURI().startsWith("/mfa/") ? "mfa" : "login";
            Long ipCount = redis.execute(INCREMENT, List.of("iam:throttle:ip:" + ip));
            Long userCount = redis.execute(INCREMENT, List.of("iam:throttle:user:" + bucket + ":" + user + ":" + ip));
            if (ipCount == null || userCount == null || ipCount > 100 || userCount > (req.getRequestURI().startsWith("/passkeys/") ? 60 : 10)) {
                res.setHeader("Retry-After", "60");
                res.sendError(429);
                return;
            }
        } catch (org.springframework.data.redis.RedisConnectionFailureException e) {
            res.sendError(503);
            return;
        }
        chain.doFilter(req, res);
    }
}
