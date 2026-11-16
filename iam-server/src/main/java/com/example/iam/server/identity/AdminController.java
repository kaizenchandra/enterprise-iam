package com.example.iam.server.identity;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    private final JdbcTemplate db;
    private final PasswordEncoder encoder;
    private final com.example.iam.server.token.TrackedAuthorizationService authorizations;

    public AdminController(JdbcTemplate db, PasswordEncoder encoder, com.example.iam.server.token.TrackedAuthorizationService authorizations) {
        this.db = db;
        this.encoder = encoder;
        this.authorizations = authorizations;
    }

    @PostMapping("/users")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, String> create(@Valid @RequestBody NewUser u) {
        String email;
        try {
            com.example.iam.server.account.AccountActions.password(u.password());
            email = com.example.iam.server.account.AccountSettings.email(u.email());
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid account input");
        }
        String id = UUID.randomUUID().toString();
        db.update("insert into users(id,username,password_hash,state,email) values (?,?,?,'PENDING_VERIFICATION',?)", id, u.username(), encoder.encode(u.password()), email);
        audit("USER_CREATED", id);
        return Map.of("id", id, "state", "PENDING_VERIFICATION");
    }

    @GetMapping("/users")
    public List<Map<String, Object>> users(@RequestParam(defaultValue = "0") @Min(0) @Max(21474836) int page) {
        return db.queryForList("select id,username,state,version from users order by id limit 100 offset ?", Math.multiplyExact(page, 100));
    }

    @GetMapping("/users/{id}")
    public Map<String, Object> user(@PathVariable String id) {
        return db.queryForList("select id,username,state,version from users where id=?", id).stream().findFirst().orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    // Profile edits cannot mutate credentials, verified email bindings, or account state.
    @PatchMapping("/users/{id}")
    @Transactional
    public Map<String, Object> update(@PathVariable String id, @Valid @RequestBody ProfileUpdate profile) {
        authorizations.lockPrincipal(id);
        var current = user(id);
        if ("DELETED".equals(current.get("state"))) throw new ResponseStatusException(HttpStatus.CONFLICT);
        int changed = db.update("update users set username=?,version=version+1 where id=? and version=?",
                profile.username(), id, profile.version());
        if (changed != 1) throw new ResponseStatusException(HttpStatus.CONFLICT, "Stale user version");
        audit("USER_PROFILE_UPDATED", id);
        return user(id);
    }

    @PostMapping("/users/{id}/deactivate")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void deactivate(@PathVariable String id) {
        transition(id, UserState.DISABLED);
        authorizations.revokeUser(id);
    }

    // Logical deletion retains security evidence and prevents accidental identity reuse.
    @DeleteMapping("/users/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Transactional
    public void delete(@PathVariable String id) {
        transition(id, UserState.DELETED);
        authorizations.revokeUser(id);
    }

    @PostMapping("/users/{id}/suspend")
    @Transactional
    public void suspend(@PathVariable String id) {
        transition(id, UserState.SUSPENDED);
        authorizations.revokeUser(id);
    }

    // Activation is an administrator attestation; it never marks an email verified.
    @PostMapping("/users/{id}/activate")
    @Transactional
    public void activate(@PathVariable String id) {
        transition(id, UserState.ACTIVE);
    }

    private void transition(String id, UserState target) {
        authorizations.lockPrincipal(id);
        var rows = db.queryForList("select state from users where id=? for update", id);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        var state = UserState.valueOf(rows.getFirst().get("state").toString());
        if (!state.canTransitionTo(target)) throw new ResponseStatusException(HttpStatus.CONFLICT);
        db.update("update users set state=?,version=version+1 where id=?", target.name(), id);
        audit("USER_" + target, id);
    }

    @PostMapping("/organizations")
    @ResponseStatus(HttpStatus.CREATED)
    @Transactional
    public Map<String, String> organization(@Valid @RequestBody Organization o) {
        String id = UUID.randomUUID().toString();
        db.update("insert into organizations(id,name) values (?,?)", id, o.name());
        audit("ORGANIZATION_CREATED", id);
        return Map.of("id", id);
    }

    @GetMapping("/organizations")
    public List<Map<String, Object>> organizations(@RequestParam(defaultValue = "0") @Min(0) @Max(21474836) int page) {
        return db.queryForList("select id,name from organizations order by id limit 100 offset ?", page * 100);
    }

    private void audit(String type, String id) {
        db.update("insert into security_audit_events(id,event_type,subject_id) values (?,?,?)", UUID.randomUUID().toString(), type, id);
    }

    public record ProfileUpdate(@NotBlank @Size(max = 128) String username, @NotNull @PositiveOrZero Long version) {
    }

    public record NewUser(@NotBlank @Size(max = 128) String username,
                          @NotBlank @Size(min = 14, max = 64) String password, @Email @Size(max = 254) String email) {
    }

    public record Organization(@NotBlank @Size(max = 128) String name) {
    }
}
