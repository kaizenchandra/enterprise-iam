package com.example.iam.server.token;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * Bind the request before security filters; publish successful token responses only after commit.
 */
@Component
@Order(-102)
public class ProtocolTransactionFilter extends OncePerRequestFilter {
    public static final String REQUEST_BIRTH = "iam.request.birth";
    private final TransactionTemplate tx;
    private final org.springframework.jdbc.core.JdbcTemplate db;

    public ProtocolTransactionFilter(PlatformTransactionManager transactions, org.springframework.jdbc.core.JdbcTemplate db) {
        this.db = db;
        tx = new TransactionTemplate(transactions);
        tx.setTimeout(10);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {
        var previous = RequestContextHolder.getRequestAttributes();
        var attributes = new ServletRequestAttributes(request, response);
        RequestContextHolder.setRequestAttributes(attributes);
        try {
            if ("POST".equals(request.getMethod()) && (request.getRequestURI().equals("/login") || request.getRequestURI().equals("/session/login")))
                request.setAttribute(REQUEST_BIRTH, db.queryForObject("select clock_timestamp()", java.sql.Timestamp.class).toInstant());
            if (!request.getRequestURI().equals("/oauth2/token")
                    && !request.getRequestURI().equals("/oauth2/revoke")) {
                chain.doFilter(request, response);
                return;
            }
            var buffered = new ContentCachingResponseWrapper(response);
            try {
                tx.executeWithoutResult(status -> {
                    try {
                        chain.doFilter(request, buffered);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    } catch (ServletException e) {
                        throw new IllegalStateException(e);
                    }
                });
                buffered.copyBodyToResponse();
            } catch (RuntimeException e) {
                // Includes transaction/commit failures: never release a token from a rolled-back save.
                if (response.isCommitted()) throw e;
                response.reset();
                response.setStatus(503);
                response.setContentType("application/json");
                response.setHeader("Cache-Control", "no-store");
                response.getWriter().write("{\"error\":\"temporarily_unavailable\"}");
            }
        } catch (org.springframework.dao.DataAccessException | org.springframework.transaction.TransactionException e) {
            // A failed authoritative session check or Redis read must never admit browser activity.
            if (response.isCommitted()) throw e;
            response.reset();
            response.setStatus(503);
            response.setContentType("application/json");
            response.setHeader("Cache-Control", "no-store");
            response.getWriter().write("{\"error\":\"temporarily_unavailable\"}");
        } finally {
            RequestContextHolder.setRequestAttributes(previous);
        }
    }
}
