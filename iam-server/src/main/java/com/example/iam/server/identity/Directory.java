package com.example.iam.server.identity;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class Directory implements UserDetailsService {
    private final JdbcTemplate db;

    public Directory(JdbcTemplate db) {
        this.db = db;
    }

    @Override
    public UserDetails loadUserByUsername(String name) {
        var rows = db.queryForList("select id,username,password_hash,state from users where username=?", name);
        if (rows.isEmpty()) throw new UsernameNotFoundException("Invalid credentials");
        var r = rows.getFirst();
        return User.withUsername(r.get("id").toString()).password(r.get("password_hash").toString()).authorities("USER")
                .disabled(!"ACTIVE".equals(r.get("state"))).build();
    }
}
