package com.example.iam.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Controller
public class SessionPageController {
    private final OAuth2AuthorizedClientRepository clients;
    private final RestClient api;

    public SessionPageController(OAuth2AuthorizedClientRepository clients, ClientRegistrationRepository registrations) {
        this.clients = clients;
        var factory = new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).followRedirects(HttpClient.Redirect.NEVER).build());
        factory.setReadTimeout(Duration.ofSeconds(5));
        api = RestClient.builder().requestFactory(factory).baseUrl(registrations.findByRegistrationId("iam").getProviderDetails().getIssuerUri()).build();
    }

    private OAuth2AuthorizedClient client(Authentication identity, HttpServletRequest request) {
        OAuth2AuthorizedClient client = clients.loadAuthorizedClient("iam-management", identity, request);
        // Deliberately reauthorize rather than racing refresh-token rotation across BFF nodes.
        return client != null && client.getAccessToken().getExpiresAt() != null && client.getAccessToken().getExpiresAt().isAfter(Instant.now().plusSeconds(15)) ? client : null;
    }

    private Page page(OAuth2AuthorizedClient client, UUID after) {
        return api.get().uri(b -> {
                    b.path("/api/v1/users/me/sessions").queryParam("limit", 50);
                    if (after != null) b.queryParam("after", after);
                    return b.build();
                })
                .headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue())).retrieve().body(Page.class);
    }

    @GetMapping("/sessions")
    public String sessions(@RequestParam(required = false) UUID after, Authentication identity, HttpServletRequest request, HttpServletResponse response, Model model) {
        response.setHeader("Cache-Control", "no-store");
        var client = client(identity, request);
        if (client == null) return "redirect:/oauth2/authorization/iam-management";
        try {
            var page = page(client, after);
            model.addAttribute("page", page);
            return "sessions";
        } catch (RestClientResponseException e) {
            return error(e.getStatusCode().value(), identity, request, response, model);
        } catch (RestClientException e) {
            return error(503, identity, request, response, model);
        }
    }

    @PostMapping("/sessions/{id}/revoke")
    public String revoke(@PathVariable UUID id, Authentication identity, HttpServletRequest request, HttpServletResponse response, Model model) {
        response.setHeader("Cache-Control", "no-store");
        var client = client(identity, request);
        if (client == null) return "redirect:/sessions";
        try {
            api.delete().uri("/api/v1/users/me/sessions/{id}", id).headers(h -> h.setBearerAuth(client.getAccessToken().getTokenValue())).retrieve().toBodilessEntity();
            // Current-session revocation also revokes the management grant. End this local session immediately.
            try {
                page(client, null);
            } catch (RestClientResponseException e) {
                if (e.getStatusCode().value() == 403) {
                    var session = request.getSession(false);
                    if (session != null) {
                        try {
                            session.invalidate();
                        } catch (IllegalStateException alreadyInvalidated) {/* Concurrent back-channel logout won. */}
                    }
                    return "redirect:/signed-out";
                }
                throw e;
            }
            return "redirect:/sessions";
        } catch (RestClientResponseException e) {
            return error(e.getStatusCode().value(), identity, request, response, model);
        } catch (RestClientException e) {
            return error(503, identity, request, response, model);
        }
    }

    private String error(int status, Authentication identity, HttpServletRequest request, HttpServletResponse response, Model model) {
        if (status == 401 || status == 403) {
            clients.removeAuthorizedClient("iam-management", identity, request, response);
            response.setStatus(409);
            model.addAttribute("message", "Session access has ended. Reconnect to continue.");
        } else {
            response.setStatus(status == 404 ? 404 : 503);
            model.addAttribute("message", status == 404 ? "That session is unavailable. It may already have been removed." : "Session management is temporarily unavailable. Refresh the list before retrying.");
        }
        return "session-error";
    }

    @GetMapping("/signed-out")
    public String signedOut(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        return "signed-out";
    }

    public record Item(UUID id, Instant createdAt, Instant lastSeenAt, Instant idleExpiresAt, Instant absoluteExpiresAt,
                       String status, boolean current) {
    }

    public record Page(List<Item> items, UUID nextCursor) {
    }
}
