package com.example.iam.server.authorization;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DecisionController {
    private final JdbcTemplate db;

    public DecisionController(JdbcTemplate db) {
        this.db = db;
    }

    @PostMapping("/api/v1/authorization/decisions")
    public Decision decide(JwtAuthenticationToken identity, @Valid @RequestBody Request request) {
        // Subject always comes from the validated token; resource tenant comes from authoritative data.
        Integer count = db.queryForObject("""
                select count(*) from user_role_assignments a
                join organization_memberships m on m.user_id=a.user_id and m.organization_id=a.organization_id
                join users u on u.id=a.user_id
                join role_permissions p on p.role_id=a.role_id
                join protected_resources r on r.id=? and r.organization_id=a.organization_id
                where a.user_id=? and a.organization_id=? and p.permission=? and u.state='ACTIVE'
                and (a.resource_id is null or a.resource_id=r.id)
                """, Integer.class, request.resourceId(), identity.getName(), request.tenantId(), request.action());
        boolean allow = count != null && count > 0;
        return new Decision(allow ? "ALLOW" : "DENY", allow ? "PERMISSION_GRANTED" : "INSUFFICIENT_PERMISSION", "database-current");
    }

    public record Request(@NotBlank @Size(max = 128) String tenantId, @NotBlank @Size(max = 128) String action,
                          @NotBlank @Size(max = 128) String resourceId) {
    }

    public record Decision(String decision, String reasonCode, String policyVersion) {
    }
}
