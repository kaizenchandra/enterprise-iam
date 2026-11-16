package com.example.iam.server.account;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Locale;

@Component
public class AccountSettings {
    public final boolean enabled, deliveryEnabled;
    public final String origin, from;
    private final TextEncryptor encryption;
    private final ObjectMapper json;

    public AccountSettings(ObjectMapper json, @Value("${iam.account.enabled:false}") boolean enabled,
                           @Value("${iam.account.delivery-enabled:true}") boolean deliveryEnabled, @Value("${iam.account.public-origin:https://localhost:9000}") String origin,
                           @Value("${iam.account.allow-http:false}") boolean http, @Value("${iam.account.from:identity@example.invalid}") String from,
                           @Value("${ACCOUNT_ENCRYPTION_PASSWORD:}") String password, @Value("${ACCOUNT_ENCRYPTION_SALT:}") String salt) {
        this.json = json;
        this.enabled = enabled;
        this.deliveryEnabled = deliveryEnabled;
        this.from = email(from);
        URI uri = URI.create(origin);
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null || (uri.getPath() != null && !uri.getPath().isEmpty()) || !("https".equals(uri.getScheme()) || http && "http".equals(uri.getScheme())))
            throw new IllegalArgumentException("Invalid account public origin");
        this.origin = origin;
        if (enabled && (password.length() < 32 || !salt.matches("[a-fA-F0-9]{32}")))
            throw new IllegalArgumentException("Account delivery encryption inputs required");
        encryption = enabled ? Encryptors.delux(password, salt) : null;
    }

    public static String email(String email) {
        if (email == null) return null;
        String value = email.strip().toLowerCase(Locale.ROOT);
        if (value.length() > 254 || !value.matches("[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\.[a-z]{2,63}"))
            throw new IllegalArgumentException("Invalid email");
        return value;
    }

    public String seal(String email, String body) {
        try {
            return encryption.encrypt(json.writeValueAsString(new Envelope(email, body)));
        } catch (Exception e) {
            throw new IllegalStateException("Account encryption failed");
        }
    }

    public Envelope open(String value) {
        try {
            return json.readValue(encryption.decrypt(value), Envelope.class);
        } catch (Exception e) {
            throw new IllegalStateException("Account decryption failed");
        }
    }

    public record Envelope(String email, String body) {
    }
}
