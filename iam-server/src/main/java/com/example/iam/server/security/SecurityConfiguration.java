package com.example.iam.server.security;

import com.example.iam.server.mfa.MfaService;
import com.example.iam.server.session.SessionRevocationHandler;
import com.example.iam.server.token.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.List;

@Configuration
public class SecurityConfiguration {
    private static void requireS256(List<AuthenticationProvider> providers) {
        for (var provider : providers) {
            if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider codeProvider) {
                codeProvider.setAuthenticationValidator(new OAuth2AuthorizationCodeRequestAuthenticationValidator()
                        .andThen(context -> {
                            var request = context.<OAuth2AuthorizationCodeRequestAuthenticationToken>getAuthentication();
                            if (!"S256".equals(request.getAdditionalParameters().get("code_challenge_method"))) {
                                throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error("invalid_request"), request);
                            }
                        }));
            }
        }
    }

    private static AuthorizationDecision decision(Authentication authentication, String audience, String scope) {
        boolean allowed = authentication instanceof JwtAuthenticationToken jwt
                && jwt.getToken().getAudience().contains(audience)
                && "at+jwt".equals(jwt.getToken().getHeaders().get("typ"))
                && authentication.getAuthorities().stream().anyMatch(authority -> authority.getAuthority().equals(scope));
        return new AuthorizationDecision(allowed);
    }

    private static AuthorizationDecision adminDecision(Authentication authentication, org.springframework.jdbc.core.JdbcTemplate db, TrackedAuthorizationService grants) {
        if (!decision(authentication, "iam-admin", "SCOPE_iam.admin").isGranted())
            return new AuthorizationDecision(false);
        var jwt = (JwtAuthenticationToken) authentication;
        if (jwt.getName().startsWith("client:")) return new AuthorizationDecision(true); // Existing machine automation.
        boolean active = Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from platform_administrators a join users u on u.id=a.user_id where u.id=? and u.state='ACTIVE')", Boolean.class, jwt.getName()));
        return new AuthorizationDecision(active && grants.findByToken(jwt.getToken().getTokenValue(), org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN) != null);
    }

    @Bean
    FilterRegistrationBean<RefreshGuard> disableServletRegistration(RefreshGuard guard) {
        var registration = new FilterRegistrationBean<>(guard);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    org.springframework.security.core.session.SessionRegistry distributedSessionRegistry(org.springframework.session.data.redis.RedisIndexedSessionRepository sessions) {
        return new org.springframework.session.security.SpringSessionBackedSessionRegistry<>(sessions);
    }

    @Bean
    org.springframework.security.authentication.AuthenticationManager authenticationManager(org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    PasswordEncoder passwords() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    AuthorizationServerSettings settings(@Value("${iam.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    @Order(1)
    SecurityFilterChain protocol(HttpSecurity http, RefreshGuard guard, SessionRevocationHandler revocation,
                                 TrackedAuthorizationService authorizations, MfaService mfa, JdbcTemplate db,
                                 com.example.iam.server.client.PrivateKeyClientAuthentication privateKeys, AuthUi ui) throws Exception {
        var server = OAuth2AuthorizationServerConfigurer.authorizationServer();
        var defaultLogout = new OidcLogoutAuthenticationSuccessHandler();
        http.securityMatcher(server.getEndpointsMatcher())
                .with(server, configuration -> configuration
                        .clientAuthentication(client -> client.authenticationProviders(providers -> {
                            for (int i = 0; i < providers.size(); i++)
                                if (providers.get(i) instanceof JwtClientAssertionAuthenticationProvider)
                                    providers.set(i, privateKeys.provider());
                        }))
                        .oidc(oidc -> oidc.providerConfigurationEndpoint(metadata -> metadata.providerConfigurationCustomizer(builder -> builder.claim("backchannel_logout_supported", true).claim("backchannel_logout_session_supported", true))).logoutEndpoint(logout -> logout.logoutResponseHandler((request, response, authentication) -> {
                            revocation.logout(request, response, authentication);
                            defaultLogout.onAuthenticationSuccess(request, response, authentication);
                        })))
                        .tokenRevocationEndpoint(endpoint -> endpoint.authenticationProviders(providers -> {
                            for (int i = 0; i < providers.size(); i++) {
                                if (providers.get(i) instanceof OAuth2TokenRevocationAuthenticationProvider) {
                                    providers.set(i, new OAuth2TokenRevocationAuthenticationProvider(
                                            new RevocationAuthorizationService(authorizations, db)));
                                }
                            }
                        }))
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestConverter(new AuthorizationBirthConverter(authorizations))
                                .authenticationProviders(SecurityConfiguration::requireS256)))
                .authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                .exceptionHandling(errors -> errors.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint(ui.page("/auth/login")), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .addFilterAfter(guard, BasicAuthenticationFilter.class)
                .addFilterAfter(new SessionActivityFilter(authorizations), org.springframework.security.web.csrf.CsrfFilter.class)
                .addFilterAfter(new SessionAssuranceFilter(mfa, db, authorizations, ui), SessionActivityFilter.class);
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain api(HttpSecurity http, org.springframework.jdbc.core.JdbcTemplate db, TrackedAuthorizationService grants) throws Exception {
        http.securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sessions -> sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()))
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/api/v1/organizations/*/members", "/api/v1/organizations/*/members/*").access((identity, context) -> adminDecision(identity.get(), db, grants))
                        .requestMatchers("/api/v1/admin/**").access((identity, context) -> adminDecision(identity.get(), db, grants))
                        .requestMatchers(org.springframework.http.HttpMethod.GET, "/api/v1/users/me/sessions").access((identity, context) -> decision(identity.get(), "iam-session-management", "SCOPE_sessions.read"))
                        .requestMatchers(org.springframework.http.HttpMethod.DELETE, "/api/v1/users/me/sessions/*").access((identity, context) -> decision(identity.get(), "iam-session-management", "SCOPE_sessions.write"))
                        .requestMatchers("/api/v1/authorization/**").access((identity, context) -> decision(identity.get(), "enterprise-api", "SCOPE_decision.write"))
                        .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    @Order(3)
    SecurityFilterChain browser(HttpSecurity http, SessionRevocationHandler revocation, BrowserLoginSuccess loginSuccess, AuthUi ui,
                                TrackedAuthorizationService authorizations, MfaService mfa, JdbcTemplate db) throws Exception {
        http.authorizeHttpRequests(requests -> requests
                        .requestMatchers("/login", "/session/bootstrap", "/session/login", "/error", "/actuator/health/**", "/account/**", "/auth.css", "/mfa.js", "/account-token.js", "/passkeys.js", "/passkeys/login/**").permitAll().anyRequest().authenticated())
                .exceptionHandling(errors -> errors.authenticationEntryPoint((request, response, error) -> {
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"detail\":\"Sign in to continue.\",\"redirect\":\"" + ui.page("/auth/login") + "\"}");
                }))
                .formLogin(login -> login.loginPage("/login").successHandler((request, response, authentication) -> {
                    var session = request.getSession();
                    authorizations.registerSession(TrackedAuthorizationService.digest(session.getId()).substring(0, 32), authentication.getName(),
                            (java.time.Instant) request.getAttribute(ProtocolTransactionFilter.REQUEST_BIRTH));
                    session.setAttribute(TrackedAuthorizationService.SESSION, TrackedAuthorizationService.digest(session.getId()).substring(0, 32));
                    session.removeAttribute("mfa_subject");
                    session.removeAttribute("mfa_attempts");
                    session.removeAttribute("recovery_codes");
                    loginSuccess.success(request, response, authentication);
                }))
                .addFilterAfter(new SessionActivityFilter(authorizations), org.springframework.security.web.csrf.CsrfFilter.class)
                .addFilterAfter(new SessionAssuranceFilter(mfa, db, authorizations, ui), SessionActivityFilter.class)
                .logout(logout -> logout.addLogoutHandler(revocation));
        return http.build();
    }
}
