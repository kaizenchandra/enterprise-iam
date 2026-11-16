package com.example.iam.server.oauth2;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

@Configuration
@Profile("local")
public class LocalBootstrap {
    private static void machine(RegisteredClientRepository clients, PasswordEncoder encoder, String id, String secret, Set<String> scopes) {
        if (clients.findByClientId(id) == null)
            clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(id).clientSecret(encoder.encode(secret)).clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scopes(s -> s.addAll(scopes)).tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build()).build());
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.length() < 16)
            throw new IllegalStateException(name + " must be supplied (16+ characters)");
        return value;
    }

    @Bean
    CommandLineRunner bootstrap(JdbcTemplate db, PasswordEncoder encoder, RegisteredClientRepository clients) {
        return args -> {
            String password = required("DEMO_PASSWORD");
            if (db.queryForObject("select count(*) from users where username='employee'", Integer.class) == 0)
                db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", UUID.randomUUID().toString(), "employee", encoder.encode(password));
            for (int i = 0; i < 2; i++) {
                String name = i == 0 ? "portal-a" : "portal-b";
                int port = Integer.parseInt(System.getenv().getOrDefault(i == 0 ? "PORTAL_A_PORT" : "PORTAL_B_PORT", String.valueOf(8080 + i)));
                if (clients.findByClientId(name) == null)
                    clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId(name).clientSecret(encoder.encode(required("PORTAL_SECRET")))
                            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                            .redirectUri("http://localhost:" + port + "/login/oauth2/code/iam").postLogoutRedirectUri("http://localhost:" + port)
                            .scope("openid").scope("profile").scope("orders.read").scope("decision.write")
                            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
                            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).authorizationCodeTimeToLive(Duration.ofSeconds(60)).refreshTokenTimeToLive(Duration.ofHours(8)).reuseRefreshTokens(false).build()).build());
                var portal = clients.findByClientId(name);
                String endpoint = System.getenv().getOrDefault(i == 0 ? "PORTAL_A_BACKCHANNEL_URI" : "PORTAL_B_BACKCHANNEL_URI", "http://localhost:" + port + "/logout/connect/back-channel/iam");
                clients.save(RegisteredClient.from(portal).scope("sessions.read").scope("sessions.write")
                        .redirectUris(uris -> {
                            uris.clear();
                            uris.add("http://localhost:" + port + "/login/oauth2/code/iam");
                            uris.add("http://localhost:" + port + "/login/oauth2/code/iam-management");
                        })
                        .postLogoutRedirectUris(uris -> {
                            uris.clear();
                            uris.add("http://localhost:" + port);
                        }).clientSettings(ClientSettings.withSettings(portal.getClientSettings().getSettings())
                                .setting("backchannel_logout_uri", endpoint).setting("backchannel_logout_session_required", true).build()).build());
            }
            // Local Next.js console: separate app and owner-session authorizations use the same
            // confidential client, with exact callback and back-channel endpoints.
            if (clients.findByClientId("next-console") == null)
                clients.save(RegisteredClient.withId(UUID.randomUUID().toString()).clientId("next-console")
                        .clientSecret(encoder.encode(required("PORTAL_SECRET")))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("http://localhost:3000/api/auth/callback")
                        .scope("openid").scope("profile").scope("orders.read").scope("decision.write")
                        .scope("sessions.read").scope("sessions.write")
                        .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false)
                                .setting("backchannel_logout_uri", "http://localhost:3000/api/auth/backchannel")
                                .setting("backchannel_logout_session_required", true).build())
                        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5))
                                .authorizationCodeTimeToLive(Duration.ofSeconds(60)).build()).build());
            var console = clients.findByClientId("next-console");
            clients.save(RegisteredClient.from(console).scope("iam.admin").build());
            // Opt-in local human administrator. Never rotate existing credentials or promote employee.
            String adminPassword = System.getenv("ADMIN_PASSWORD");
            if (adminPassword != null && !adminPassword.isBlank()
                    && db.queryForObject("select count(*) from users where username='admin'", Integer.class) == 0) {
                com.example.iam.server.account.AccountActions.password(adminPassword);
                String adminId = UUID.randomUUID().toString();
                new org.springframework.transaction.support.TransactionTemplate(new org.springframework.jdbc.datasource.DataSourceTransactionManager(db.getDataSource())).executeWithoutResult(status -> {
                    db.update("insert into users(id,username,password_hash,state) values (?,?,?,'ACTIVE')", adminId, "admin", encoder.encode(adminPassword));
                    db.update("insert into platform_administrators(user_id) values (?)", adminId);
                    db.update("insert into security_audit_events(id,event_type,subject_id) values (?,'LOCAL_ADMIN_PROVISIONED',?)", UUID.randomUUID().toString(), adminId);
                });
            }
            machine(clients, encoder, "order-service", required("MACHINE_SECRET"), Set.of("orders.read"));
            machine(clients, encoder, "admin-cli", required("ADMIN_SECRET"), Set.of("iam.admin"));
        };
    }
}
