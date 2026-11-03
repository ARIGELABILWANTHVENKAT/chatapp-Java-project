import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * SecureChat v2: zero-dependency Java relay server + HTML client.
 * The server is "zero-knowledge": messages are encrypted in the browser (AES-256-GCM),
 * so the server only stores/relays ciphertext. It handles:
 *  - realtime delivery (Server-Sent Events), user presence
 *  - self-destruct timers and burn-after-read
 *  - emoji reactions, duplicate-safe delivery for the offline queue (cid)
 */
public class ChatServer {
    // mode: 0 = normal, 1 = timed self-destruct, 2 = burn after read
    record Msg(int id, String cid, String user, String time, int mode, long exp, String cipher) {
        String json() {
            long left = exp > 0 ? Math.max(0, (exp - System.currentTimeMillis()) / 1000) : 0;
            return "{\"id\":" + id + ",\"cid\":" + q(cid) + ",\"user\":" + q(user) + ",\"time\":" + q(time)
                 + ",\"mode\":" + mode + ",\"left\":" + left + ",\"cipher\":\"" + cipher + "\"}";
        }
    }
    static class Client { String user; OutputStream out; }

    static final int MAX = 8_000_000;
    static final List<Msg> history = new CopyOnWriteArrayList<>();
    static final List<Client> clients = new CopyOnWriteArrayList<>();
    static final Map<Integer, Map<String, String>> reactions = new ConcurrentHashMap<>();
    static final Set<String> seenCids = ConcurrentHashMap.newKeySet();
    static final Set<Integer> burning = ConcurrentHashMap.newKeySet();
    static final Set<String> EMOJI = Set.of("😊", "😂", "😍", "👍", "😢", "😡");
    static final ScheduledExecutorService timer = Executors.newScheduledThreadPool(2);
    static final AtomicInteger ids = new AtomicInteger();
    static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("HH:mm");

    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", ex -> send(ex, 200, "text/html; charset=utf-8", Files.readAllBytes(Path.of("index.html"))));
        server.createContext("/events", ChatServer::events);
        server.createContext("/send", ChatServer::receive);
        server.createContext("/react", ChatServer::react);
        server.createContext("/read", ChatServer::read);
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("SecureChat running -> http://localhost:8080  (use localhost so browser encryption is enabled)");
    }

    // One long-lived SSE connection per user
    static void events(HttpExchange ex) throws IOException {
        String user = cut(param(ex.getRequestURI().getRawQuery(), "user"), 20);
        if (user.isBlank()) user = "guest" + new Random().nextInt(99);
        ex.getResponseHeaders().add("Content-Type", "text/event-stream");
        ex.getResponseHeaders().add("Cache-Control", "no-cache");
        ex.sendResponseHeaders(200, 0);
        Client c = new Client();
        c.user = user;
        c.out = ex.getResponseBody();
        try {
            clients.add(c);
            for (Msg m : history) {
                write(c, "msg", m.json());
                if (reactions.containsKey(m.id())) write(c, "react", reactJson(m.id()));
            }
            broadcastUsers();
            while (true) {
                Thread.sleep(15000);
                synchronized (c) { c.out.write(": ping\n\n".getBytes()); c.out.flush(); }
            }
        } catch (Exception ignored) {
        } finally {
            clients.remove(c);
            broadcastUsers();
            try { ex.close(); } catch (Exception ignored) {}
        }
    }

    static void receive(HttpExchange ex) throws IOException {
        byte[] raw = ex.getRequestBody().readNBytes(MAX);
        if (raw.length >= MAX) { send(ex, 413, "text/plain", "too large".getBytes()); return; }
        String body = new String(raw, StandardCharsets.UTF_8);
        String user = cut(param(body, "user"), 20);
        String cid = param(body, "cid").replaceAll("[^A-Za-z0-9]", "");
        String cipher = param(body, "cipher").replaceAll("[^A-Za-z0-9+/=:]", "");
        int mode = num(param(body, "mode"), 0, 2), ttl = num(param(body, "ttl"), 0, 300);
        if (user.isBlank() || cid.isEmpty() || cipher.length() < 4) { send(ex, 400, "text/plain", "bad".getBytes()); return; }
        if (!seenCids.add(cid)) { send(ex, 200, "text/plain", "dup".getBytes()); return; } // idempotent resend
        if (mode == 1 && ttl == 0) mode = 0;
        Msg m = new Msg(ids.incrementAndGet(), cid, user, LocalTime.now().format(FMT), mode,
                        mode == 1 ? System.currentTimeMillis() + ttl * 1000L : 0, cipher);
        history.add(m);
        if (mode == 0) log(m);
        else if (mode == 1) timer.schedule(() -> destroy(m.id()), ttl, TimeUnit.SECONDS);
        broadcast("msg", m.json());
        send(ex, 200, "text/plain", "ok".getBytes());
    }

    static void react(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readNBytes(2000), StandardCharsets.UTF_8);
        int id = num(param(body, "id"), 0, Integer.MAX_VALUE);
        String user = cut(param(body, "user"), 20), e = param(body, "emoji");
        if (EMOJI.contains(e) && history.stream().anyMatch(m -> m.id() == id)) {
            Map<String, String> r = reactions.computeIfAbsent(id, k -> new ConcurrentHashMap<>());
            if (e.equals(r.get(user))) r.remove(user); else r.put(user, e);
            broadcast("react", reactJson(id));
        }
        send(ex, 200, "text/plain", "ok".getBytes());
    }

    // First read by someone other than the sender starts an 8-second burn
    static void read(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readNBytes(2000), StandardCharsets.UTF_8);
        int id = num(param(body, "id"), 0, Integer.MAX_VALUE);
        String user = cut(param(body, "user"), 20);
        for (Msg m : history)
            if (m.id() == id && m.mode() == 2 && !m.user().equals(user) && burning.add(id)) {
                broadcast("burn", "{\"id\":" + id + ",\"secs\":8}");
                timer.schedule(() -> destroy(id), 8, TimeUnit.SECONDS);
            }
        send(ex, 200, "text/plain", "ok".getBytes());
    }

    static void destroy(int id) {
        history.removeIf(m -> m.id() == id);
        reactions.remove(id);
        broadcast("del", String.valueOf(id));
    }
    // The server can only see ciphertext; this log proves it.
    static void log(Msg m) {
        try {
            String c = m.cipher();
            String line = m.id() + "|" + m.time() + "|" + m.user() + "|" + c.length() + " chars|" + c.substring(0, Math.min(48, c.length())) + "...\n";
            Files.writeString(Path.of("server_log.txt"), line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
    }
    static String reactJson(int id) {
        StringJoiner j = new StringJoiner(",", "{", "}");
        reactions.getOrDefault(id, Map.of()).forEach((u, e) -> j.add(q(u) + ":" + q(e)));
        return "{\"id\":" + id + ",\"r\":" + j + "}";
    }
    static void broadcast(String ev, String data) { for (Client c : clients) write(c, ev, data); }
    static void broadcastUsers() {
        StringJoiner j = new StringJoiner(",", "[", "]");
        for (Client c : clients) j.add(q(c.user));
        broadcast("users", j.toString());
    }
    static void write(Client c, String ev, String data) {
        try {
            synchronized (c) {
                c.out.write(("event: " + ev + "\ndata: " + data + "\n\n").getBytes(StandardCharsets.UTF_8));
                c.out.flush();
            }
        } catch (IOException e) { clients.remove(c); }
    }
    static void send(HttpExchange ex, int code, String type, byte[] b) throws IOException {
        ex.getResponseHeaders().add("Content-Type", type);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }
    static String param(String s, String name) {
        if (s == null) return "";
        for (String p : s.split("&")) {
            String[] kv = p.split("=", 2);
            if (kv[0].equals(name) && kv.length == 2) return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
        }
        return "";
    }
    static int num(String s, int lo, int hi) { try { return Math.max(lo, Math.min(hi, Integer.parseInt(s))); } catch (Exception e) { return lo; } }
    static String cut(String s, int n) { return s.length() > n ? s.substring(0, n) : s; }
    static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", "") + "\""; }
}
