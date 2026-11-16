package com.example.iam.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Configuration
@Controller
@org.springframework.scheduling.annotation.EnableScheduling
public class WebConfiguration {
    @Bean
    OAuth2AuthorizedClientRepository sessionAuthorizedClients() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    SecurityFilterChain security(HttpSecurity h, ClientRegistrationRepository clients, com.example.iam.web.logout.JdbcOidcSessions sessions, OAuth2AuthorizedClientRepository authorizedClients) throws Exception {
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        var logout = new org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler(clients);
        logout.setPostLogoutRedirectUri("{baseUrl}");
        return h.authorizeHttpRequests(a -> a.requestMatchers("/actuator/health", "/error", "/signed-out").permitAll().anyRequest().authenticated())
                .oauth2Login(o -> o.authorizedClientRepository(authorizedClients).authorizationEndpoint(e -> e.authorizationRequestResolver(resolver))
                        .userInfoEndpoint(u -> u.oidcUserService(request -> {
                            var user = new org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService().loadUser(request);
                            if ("iam-management".equals(request.getClientRegistration().getRegistrationId())) {
                                var previous = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                                if (previous == null || !(previous.getPrincipal() instanceof OidcUser old) || !old.getSubject().equals(user.getSubject()) || !old.getIssuer().equals(user.getIssuer()) || old.getIdToken().getClaimAsString("sid") == null || !old.getIdToken().getClaimAsString("sid").equals(user.getIdToken().getClaimAsString("sid")))
                                    throw new org.springframework.security.oauth2.core.OAuth2AuthenticationException("account_mismatch");
                            }
                            return user;
                        }))
                        .successHandler((request, response, authentication) -> {
                            if ("iam-management".equals(((org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId()))
                                response.sendRedirect("/sessions");
                            else
                                new org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler().onAuthenticationSuccess(request, response, authentication);
                        }))
                .oidcLogout(oidc -> oidc.oidcSessionRegistry(sessions).backChannel(back -> back.logoutHandler(sessions)))
                .addFilterBefore(new com.example.iam.web.logout.ClientSessionGuard(sessions), org.springframework.security.web.access.intercept.AuthorizationFilter.class)
                .logout(l -> l.logoutSuccessHandler(logout))
                .exceptionHandling(e -> e.authenticationEntryPoint(new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/oauth2/authorization/iam"))).build();
    }

    @GetMapping("/")
    String home() {
        return "home";
    }

    @GetMapping("/profile")
    @ResponseBody
    Map<String, Object> profile(@AuthenticationPrincipal OidcUser user) {
        return Map.of("subject", user.getSubject(), "issuer", user.getIssuer().toString());
    }

    @GetMapping("/orders")
    @ResponseBody
    Object orders(@org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient("iam") OAuth2AuthorizedClient client) {
        return RestClient.create(System.getenv().getOrDefault("RESOURCE_URL", "http://localhost:9001")).get().uri("/api/orders").headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue())).retrieve().body(Object.class);
    }
}
