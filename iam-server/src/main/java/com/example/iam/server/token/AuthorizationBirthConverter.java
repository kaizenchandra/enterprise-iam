package com.example.iam.server.token;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.HashMap;

/**
 * Preserve Spring's parsing/validation; overwrite the reserved server birth stamp.
 * Pending consent has no issued token, so its framework request must retain a birth time.
 */
public final class AuthorizationBirthConverter implements AuthenticationConverter {
    public static final String BIRTH = "iam_server_birth";
    private final AuthenticationConverter delegate = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
    private final TrackedAuthorizationService service;

    public AuthorizationBirthConverter(TrackedAuthorizationService service) {
        this.service = service;
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        var result = delegate.convert(request);
        if (!(result instanceof OAuth2AuthorizationCodeRequestAuthenticationToken original)) return result;
        var parameters = new HashMap<>(original.getAdditionalParameters());
        parameters.put(BIRTH, service.now().toString());
        var stamped = new OAuth2AuthorizationCodeRequestAuthenticationToken(original.getAuthorizationUri(),
                original.getClientId(), (Authentication) original.getPrincipal(), original.getRedirectUri(),
                original.getState(), original.getScopes(), parameters);
        stamped.setDetails(original.getDetails());
        return stamped;
    }
}
