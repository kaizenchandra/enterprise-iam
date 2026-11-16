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
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Platform administration only; tenant membership itself never grants administration.
 */
@RestController
@RequestMapping("/api/v1/organizations/{id}/members")
public class MembershipController {
    private final JdbcTemplate db;

    public MembershipController(JdbcTemplate db) {
        this.db = db;
    }

    static void lockOrganization(JdbcTemplate db, String id) {
        if (db.queryForList("select id from organizations where id=? for update", id).isEmpty())
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Organization not found");
    }

    static void audit(JdbcTemplate db, String event, String subject) {
        db.update("insert into security_audit_events(id,event_type,subject_id) values (?,?,?)",
                UUID.randomUUID().toString(), event, subject);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public void add(@PathVariable String id, @Valid @RequestBody Member member) {
        lockOrganization(db, id);
        var states = db.queryForList("select state from users where id=? for share", member.userId());
        if (states.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found");
        if (!"ACTIVE".equals(states.getFirst().get("state")))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User must be active");
        db.update("insert into organization_memberships(user_id,organization_id) values (?,?)", member.userId(), id);
        audit(db, "MEMBERSHIP_CREATED", member.userId());
    }

    @GetMapping
    public List<Map<String, Object>> list(@PathVariable String id,
                                          @RequestParam(defaultValue = "0") @Min(0) @Max(21474836) int page) {
        if (db.queryForObject("select count(*) from organizations where id=?", Integer.class, id) == 0)
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        return db.queryForList("select user_id,organization_id from organization_memberships where organization_id=? order by user_id limit 100 offset ?",
                id, page * 100);
    }

    @DeleteMapping("/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void remove(@PathVariable String id, @PathVariable String userId) {
        lockOrganization(db, id);
        // Drop assignments too: rejoining must not silently restore previously held permissions.
        db.update("delete from user_role_assignments where organization_id=? and user_id=?", id, userId);
        if (db.update("delete from organization_memberships where organization_id=? and user_id=?", id, userId) != 1)
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Membership not found");
        audit(db, "MEMBERSHIP_REMOVED", userId);
    }

    public record Member(@NotBlank @Size(max = 36) String userId) {
    }
}
