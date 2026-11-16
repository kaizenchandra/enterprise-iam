import org.flywaydb.core.Flyway;

import java.sql.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Local maintenance helper; credentials are inherited only through the environment.
 */
public class LocalFlyway {
    public static void main(String[] args) throws Exception {
        String url = args[1], user = "iam", password = System.getenv("DB_PASSWORD");
        var flyway = Flyway.configure().dataSource(url, user, password)
                .locations("filesystem:" + args[2]).load();
        if (args[0].equals("migrate")) {
            flyway.migrate();
            return;
        }
        if (args[0].equals("validate")) {
            flyway.validate();
            return;
        }
        if (!args[0].equals("repair")) throw new IllegalArgumentException("Unknown maintenance operation");
        try (Connection connection = DriverManager.getConnection(url, user, password)) {
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute("set local lock_timeout='5s'");
                // Freeze application writes while history alone is reconciled and data is checked.
                List<String> tables = new ArrayList<>();
                try (ResultSet rows = statement.executeQuery("select tablename from pg_tables where schemaname='public' and tablename <> 'flyway_schema_history' order by tablename")) {
                    while (rows.next()) tables.add(rows.getString(1));
                }
                for (String table : tables) statement.execute("lock table public." + quote(table) + " in share mode");
                var before = fingerprint(connection, tables);
                var result = flyway.repair();
                if (!result.migrationsRemoved.isEmpty() || !result.migrationsDeleted.isEmpty())
                    throw new IllegalStateException("Unexpected repair action; review backup/history");
                flyway.validate();
                if (!before.equals(fingerprint(connection, tables)))
                    throw new IllegalStateException("Application data changed during maintenance");
                connection.commit();
                System.out.println("VERIFIED: application tables unchanged; repaired history validates");
            }
        }
    }

    private static String quote(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static Map<String, String> fingerprint(Connection connection, List<String> tables) throws Exception {
        Map<String, String> result = new TreeMap<>();
        for (String table : tables) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long count = 0;
            try (Statement statement = connection.createStatement()) {
                statement.setFetchSize(256);
                try (ResultSet rows = statement.executeQuery("select row_to_json(t)::text from public." + quote(table) + " t order by 1")) {
                    while (rows.next()) {
                        digest.update(rows.getString(1).getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        digest.update((byte) '\n');
                        count++;
                    }
                }
            }
            result.put(table, count + ":" + HexFormat.of().formatHex(digest.digest()));
        }
        return result;
    }
}
