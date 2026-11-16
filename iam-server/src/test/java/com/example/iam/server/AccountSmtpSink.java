package com.example.iam.server;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Test-only SMTP peer; Jakarta Mail performs actual message construction/transport. Never logs mail.
 */
final class AccountSmtpSink implements AutoCloseable {
    final AtomicReference<Mode> mode = new AtomicReference<>(Mode.OK);
    final List<String> messages = new CopyOnWriteArrayList<>();
    final ServerSocket server;
    final ExecutorService threads = Executors.newVirtualThreadPerTaskExecutor();

    AccountSmtpSink() {
        try {
            server = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
            threads.submit(() -> {
                while (!server.isClosed()) {
                    try {
                        Socket socket = server.accept();
                        threads.submit(() -> serve(socket));
                    } catch (IOException e) {
                        if (!server.isClosed()) throw new UncheckedIOException(e);
                    }
                }
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    int port() {
        return server.getLocalPort();
    }

    void serve(Socket socket) {
        try (socket) {
            socket.setSoTimeout(3000);
            if (mode.get() == Mode.OUTAGE) return;
            var in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            var out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            out.print("220 localhost test SMTP\r\n");
            out.flush();
            String line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("DATA")) {
                    out.print("354 End with dot\r\n");
                    out.flush();
                    var body = new StringBuilder();
                    while ((line = in.readLine()) != null && !line.equals("."))
                        body.append(line.startsWith("..") ? line.substring(1) : line).append("\r\n");
                    messages.add(body.toString());
                    if (mode.get() == Mode.LOSE_ACK) return;
                    out.print("250 queued\r\n");
                } else if (line.startsWith("QUIT")) {
                    out.print("221 bye\r\n");
                    out.flush();
                    return;
                } else out.print("250 localhost\r\n");
                out.flush();
            }
        } catch (IOException ignored) {
        }
    }

    String body(int index) {
        try {
            return new jakarta.mail.internet.MimeMessage(jakarta.mail.Session.getInstance(new Properties()), new ByteArrayInputStream(messages.get(index).getBytes(StandardCharsets.UTF_8))).getContent().toString();
        } catch (Exception e) {
            throw new IllegalStateException("Test mail parse failed");
        }
    }

    @Override
    public void close() {
        try {
            server.close();
        } catch (IOException ignored) {
        }
        threads.shutdownNow();
    }

    enum Mode {OK, OUTAGE, LOSE_ACK}
}
