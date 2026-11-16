package com.example.iam.server.authorization;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin")
public class PolicyAdminController {
    private final JdbcTemplate db;

    public PolicyAdminController(JdbcTemplate db) {
        this.db = db;
    }

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, String> role(@Valid @RequestBody Role role) {
        String id = UUID.randomUUID().toString();
        db.update("insert into roles(id,name) values (?,?)", id, role.name());
        MembershipController.audit(db, "ROLE_CREATED", id);
        return Map.of("id", id);
    }

    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public void permission(@Valid @RequestBody Permission p) {
        db.update("insert into role_permissions(role_id,permission) values (?,?)", p.roleId(), p.permission());
        MembershipController.audit(db, "ROLE_PERMISSION_CREATED", p.roleId());
    }

    @PostMapping("/role-assignments")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, String> assign(@Valid @RequestBody Assignment a) {
        MembershipController.lockOrganization(db, a.organizationId());
        if (a.resourceId() != null && db.queryForObject("select count(*) from protected_resources where id=? and organization_id=?", Integer.class, a.resourceId(), a.organizationId()) == 0)
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.BAD_REQUEST, "Resource outside organization");
        String id = UUID.randomUUID().toString();
        db.update("insert into user_role_assignments(id,user_id,organization_id,role_id,resource_id) values (?,?,?,?,?)", id, a.userId(), a.organizationId(), a.roleId(), a.resourceId());
        db.update("insert into security_audit_events(id,event_type,subject_id) values (?,'ROLE_ASSIGNED',?)", UUID.randomUUID().toString(), a.userId());
        return Map.of("id", id);
    }

    @DeleteMapping("/role-assignments/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void revoke(@PathVariable String id) {
        var rows = db.queryForList("select organization_id from user_role_assignments where id=?", id);
        if (rows.isEmpty()) throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND);
        MembershipController.lockOrganization(db, rows.getFirst().get("organization_id").toString());
        if (db.update("delete from user_role_assignments where id=?", id) != 1)
            throw new org.springframework.web.server.ResponseStatusException(HttpStatus.NOT_FOUND);
        MembershipController.audit(db, "ROLE_ASSIGNMENT_REVOKED", id);
    }

    @GetMapping("/policies")
    public List<Map<String, Object>> policies(@RequestParam(defaultValue = "0") @Min(0) @Max(21474836) int page) {
        return db.queryForList("select r.id,r.name,p.permission from roles r left join role_permissions p on p.role_id=r.id order by r.id,p.permission limit 100 offset ?", page * 100);
    }

    public record Role(@NotBlank @Size(max = 128) String name) {
    }

    public record Permission(@NotBlank String roleId, @NotBlank @Size(max = 128) String permission) {
    }

    public record Assignment(@NotBlank String userId, @NotBlank String organizationId, @NotBlank String roleId,
                             String resourceId) {
    }
}
