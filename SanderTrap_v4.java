import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.text.SimpleDateFormat;
import java.util.regex.Pattern;
import java.util.Random;

public class SanderTrap_v4 {

    // --- KONFIGURASI (Bisa diganti via ConfigManager nanti) ---
    private static final int[] PORTS = {2121, 2222, 3306, 8080, 33890};
    private static final int MAX_TARPIT_THREADS = 30; // Turun dikit buat HP aman
    private static final long TARPIT_DELAY_MS = 1500;
    private static final int MAX_INPUT_SIZE = 8192; // 8KB Limit (Anti-ReDoS)
    private static final long BLACKLIST_EXPIRY_MS = 3600000; // 1 Jam expiry per IP

    // --- FILE LOG (Polyglot: CSV + JSON Lines) ---
    private static final String CSV_FILE = "sander_v4_behavior.csv";
    private static final String JSON_FILE = "sander_v4_behavior.jsonl"; // .jsonl for Lines format
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final Random RAND = new Random();

    // --- COUNTERS ---
    private static final AtomicLong cConn = new AtomicLong(0);
    private static final AtomicLong cTarpit = new AtomicLong(0);
    private static final AtomicLong cThreat = new AtomicLong(0);
    private static final AtomicLong cPayload = new AtomicLong(0);
    
    // --- QUEUES (Terpisah biar nggak bottleneck) ---
    private static final BlockingQueue<String> csvQueue = new LinkedBlockingQueue<>(1000);
    private static final BlockingQueue<String> jsonQueue = new LinkedBlockingQueue<>(1000);

    // --- PATTERNS (Optimized & Safe) ---
    private static final Pattern SQLI_PATTERN = Pattern.compile("(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|'.*or.*'=')");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i)(<script|javascript:|onerror\\s*=|onload\\s*=)");
    private static final Pattern CMD_INJ_PATTERN = Pattern.compile("(?i)(;|\\||&&|\\$\\(|`)");

    // --- STATE MANAGEMENT (Smart Blacklist) ---
    // Map<IP, TimestampLastSeen>
    private static final ConcurrentHashMap<String, Long> blacklist = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        System.out.println("══════════════════════════════════════════════════════╗");
        System.out.println("║       SanderTrap v4.0 (God Mode Refactor)           ║");
        System.out.println("║  'Logic Adapted. Security Hardened. Polyglot Ready.' ");
        System.out.println("╚══════════════════════════════════════════════════════╝");

        // 1. Init Logs
        initLogFiles();

        // 2. Start Dual Log Writers
        new Thread(() -> writeLoop(csvQueue, CSV_FILE), "CSV-Writer").start();
        new Thread(() -> writeLoop(jsonQueue, JSON_FILE), "JSON-Writer").start();

        // 3. Start Stats & Cleanup
        new Thread(SanderTrap_v4::printStats, "Stats-Monitor").start();
        new Thread(SanderTrap_v4::cleanupBlacklist, "Blacklist-Cleanup").start();

        // 4. Start Listeners
        for (int p : PORTS) {
            new Thread(() -> listen(p), "Listener-" + p).start();
        }
        
        System.out.println("[SYSTEM] All systems operational. Waiting for victims...");
    }

    // ==========================================
    // 1. LOGGING ENGINE (Fixed & Optimized)
    // ==========================================
    private static void initLogFiles() {
        try {
            // CSV Header
            File csv = new File(CSV_FILE);
            if (!csv.exists()) {
                csv.createNewFile();
                writeFileSync(CSV_FILE, "timestamp,event,ip,port,details\n");
            }
            // JSON Lines: No header needed, just append lines
            new File(JSON_FILE).createNewFile(); 
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to init log files: " + e.getMessage());
        }
    }

    private static void writeLoop(BlockingQueue<String> queue, String filename) {
        while (true) {
            try {
                String line = queue.take(); // Blocking wait
                writeFileSync(filename, line);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Silent fail or log error
            }
        }
    }

    private static synchronized void writeFileSync(String filename, String content) {
        try (FileWriter fw = new FileWriter(filename, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            bw.write(content);
        } catch (Exception e) {}
    }

    private static void recordBehavior(String event, String ip, int port, String details) {
        String time = DATE_FORMAT.format(new Date());
        
        // CSV Format
        String csvLine = String.format("%s,%s,%s,%d,\"%s\"\n", time, event, ip, port, details.replace("\"", "'"));
        csvQueue.offer(csvLine);

        // JSON Lines Format (NO comma at end, NO array brackets)
        // Valid JSON object per line
        String jsonLine = String.format("{\"timestamp\":\"%s\",\"event\":\"%s\",\"ip\":\"%s\",\"port\":%d,\"details\":\"%s\"}\n",
                time, event, ip, port, details.replace("\"", "'").replace("\\", "\\\\"));
        jsonQueue.offer(jsonLine);
    }

    // ==========================================
    // 2. LISTENER & HANDLER (Secure & Smart)
    // ==========================================
    private static void listen(int port) {
        try (ServerSocket ss = new ServerSocket(port)) {
            System.out.println("[LISTEN] Port " + port + " active.");
            while (true) {
                Socket s = ss.accept();
                cConn.incrementAndGet();
                
                // Cek Blacklist Dulu Sebelum Spawn Thread (Optimasi)
                String ip = s.getInetAddress().getHostAddress();
                if (isBlacklisted(ip)) {
                    recordBehavior("REHIT_BLACKLIST", ip, port, "Blocked immediately");
                    try { s.close(); } catch(Exception e){}
                    continue;
                }

                new Thread(() -> process(s, port), "Handler-" + port).start();
            }
        } catch (Exception e) {
            System.err.println("[FATAL] Port " + port + " failed: " + e.getMessage());
        }
    }

    private static boolean isBlacklisted(String ip) {
        Long timestamp = blacklist.get(ip);
        if (timestamp == null) return false;
        
        // Check Expiry
        if (System.currentTimeMillis() - timestamp > BLACKLIST_EXPIRY_MS) {
            blacklist.remove(ip); // Auto remove expired
            return false;
        }
        return true;
    }

    private static void process(Socket s, int port) {
        String ip = s.getInetAddress().getHostAddress();
        
        try {
            s.setSoTimeout(2000);
            InputStream in = s.getInputStream();
            byte[] buffer = new byte[MAX_INPUT_SIZE];
            int bytesRead = in.read(buffer);
            
            if (bytesRead == -1) {
                recordBehavior("DISCONNECT", ip, port, "Client closed connection");
                return;
            }

            // --- SECURITY CHECK 1: SIZE LIMIT (Anti-ReDoS) ---
            if (bytesRead >= MAX_INPUT_SIZE) {
                cPayload.incrementAndGet();
                recordBehavior("OVERFLOW_ATTACK", ip, port, "Request exceeded 8KB limit");
                addToBlacklist(ip);
                tarpit(s, ip);
                return;
            }
            
            String requestData = new String(buffer, 0, bytesRead);
            
            // --- SECURITY CHECK 2: PATTERN MATCHING ---
            if (CMD_INJ_PATTERN.matcher(requestData).find()) {
                cPayload.incrementAndGet();
                recordBehavior("CMD_INJECTION", ip, port, "Command injection detected");
                addToBlacklist(ip);
                tarpit(s, ip);
                return;
            }

            if (SQLI_PATTERN.matcher(requestData).find() || XSS_PATTERN.matcher(requestData).find()) {
                cPayload.incrementAndGet();
                recordBehavior("WEB_EXPLOIT", ip, port, "SQLi/XSS payload detected");
                addToBlacklist(ip);
                
                // Send Fake Error Response
                sendFakeResponse(s, port, "ERROR_500");
                tarpit(s, ip);
                return;
            }

            // --- BEHAVIORAL ANALYSIS: PORT SCANNING ---
            // (Logic sederhana: jika IP ini connect ke >1 port dalam waktu singkat)
            // Untuk implementasi full butuh shared map global port history, 
            // tapi untuk v4 ini kita fokus ke payload detection dulu.
            
            // --- DEFAULT: SEND DYNAMIC BANNER ---
            String banner = getDynamicBanner(port);
            s.getOutputStream().write(banner.getBytes());
            s.getOutputStream().flush();
            recordBehavior("CONN_OK", ip, port, "Banner served");

        } catch (SocketTimeoutException e) {
            recordBehavior("TIMEOUT_SCAN", ip, port, "Silent scanner detected");
            // Jangan blacklist langsung, mungkin koneksi lambat. Tapi tarpit aja.
            tarpit(s, ip);
        } catch (Exception e) {
            // Ignore broken pipe etc
        } finally {
            try { s.close(); } catch (Exception e) {}
        }
    }

    private static void addToBlacklist(String ip) {
        blacklist.put(ip, System.currentTimeMillis());
        cThreat.incrementAndGet();
    }

    // ==========================================
    // 3. TARPIT (The Slow Death v2)
    // ==========================================
    private static void tarpit(Socket s, String ip) {
        if (cTarpit.get() >= MAX_TARPIT_THREADS) {
            try { s.close(); } catch (Exception e) {}
            return;
        }

        cTarpit.incrementAndGet();
        recordBehavior("TARPIT_ENGAGED", ip, s.getLocalPort(), "Slowing down attacker");
        
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            
            out.write("220 (SanderTrap Tarpit v4.0 - Welcome to Hell)\r\n".getBytes());
            out.flush();
            
            byte[] buf = new byte[1];
            // Loop baca & balas lambat
            while (in.read(buf) != -1) {
                out.write('.');
                out.flush();
                Thread.sleep(TARPIT_DELAY_MS);
            }
        } catch (Exception e) {
            // Client disconnected
        } finally {
            try { s.close(); } catch (Exception e) {}
            cTarpit.decrementAndGet();
        }
    }

    // ==========================================
    // 4. DYNAMIC BANNERS (Anti-Fingerprinting)
    // ==========================================
    private static String getDynamicBanner(int port) {
        int major = RAND.nextInt(9) + 1;
        int minor = RAND.nextInt(20);
        int patch = RAND.nextInt(10);
        
        if (port == 2121) return String.format("220 (vsFTPd %d.%d.%d)\r\n", major, minor, patch);
        if (port == 2222) return String.format("SSH-2.0-OpenSSH_%d.%dp%d Ubuntu-%d.%d\r\n", major, minor, patch, major, minor);
        if (port == 3306) return String.format("%d.%d.%d-0ubuntu%d.%d\u0000", major, minor, patch, major, minor);
        if (port == 8080) {
            return "HTTP/1.1 200 OK\r\n" +
                   "Server: Microsoft-IIS/" + major + ".0\r\n" +
                   "X-Frame-Options: DENY\r\n" +
                   "Content-Type: text/html\r\n" +
                   "\r\n" +
                   "<html><head><title>Login</title></head><body><h1>401 Unauthorized</h1><!-- SanderTrap Honeypot --></body></html>";
        }
        return "220 Service Ready\r\n";
    }

    private static void sendFakeResponse(Socket s, int port, String type) {
        try {
            String resp = "";
            if (type.equals("ERROR_500")) {
                resp = "HTTP/1.1 500 Internal Server Error\r\nServer: MySQL/" + RAND.nextInt(10) + ".0\r\n\r\n<h1>DB Error</h1>";
            }
            s.getOutputStream().write(resp.getBytes());
            s.getOutputStream().flush();
        } catch (Exception e) {}
    }

    // ==========================================
    // 5. UTILS: STATS & CLEANUP
    // ==========================================
    private static void printStats() {
        while (true) {
            try {
                Thread.sleep(3000);
                System.out.print("\r[STAT] Conn:" + cConn.get() + 
                                 " | Tarpit:" + cTarpit.get() + 
                                 " | Threat:" + cThreat.get() + 
                                 " | Payload:" + cPayload.get() + 
                                 " | BL_Size:" + blacklist.size() + "   ");
            } catch (Exception e) {}
        }
    }

    private static void cleanupBlacklist() {
        while (true) {
            try {
                Thread.sleep(60000); // Cek setiap 1 menit
                long now = System.currentTimeMillis();
                blacklist.entrySet().removeIf(e -> (now - e.getValue()) > BLACKLIST_EXPIRY_MS);
            } catch (Exception e) {}
        }
    }
}
