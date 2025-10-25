const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "../public")));

const cspLogPath = path.join(__dirname, "..", "csp-reports.log");

// --- MySQL connection ---
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "ehl_careers",
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err);
  } else {
    console.log("✅ Connected to MySQL (XAMPP)");
  }
});

const attackLogPath = path.join(__dirname, "..", "attack.log");

function logAttack(entry) {
  const e = Object.assign({ ts: new Date().toISOString() }, entry);
  try {
    fs.appendFileSync(attackLogPath, JSON.stringify(e) + "\n");
  } catch (err) {
    console.error("Could not write to attack log:", err);
  }
}

// --- Serve index.html ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// ==========================================================
// --- Handle form submission (VULNERABLE) ---
app.post("/submit", (req, res) => {
  const { fullname, email, item, message } = req.body;

  if (!fullname || !email || !item || !message) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Vulnerable to SQL Injection if later changed to string concatenation
  const sql =
    "INSERT INTO orders (fullname, email, item, message) VALUES (?, ?, ?, ?)";
  db.query(sql, [fullname, email, item, message], (err, result) => {
    if (err) {
      console.error("❌ Error inserting data:", err);
      return res.status(500).json({ message: "Database error" });
    }
    console.log(`✅ Order saved: ${fullname} (${item})`);
    res.json({ message: "Order placed successfully!" });
  });
});

/*
// --- Handle form submission (SANITIZED EXAMPLE) ---
app.post("/submit", (req, res) => {
  const { fullname, email, item, message } = req.body;

  // Basic input sanitization
  if (![fullname, email, item, message].every(f => typeof f === "string" && f.trim().length > 0)) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Use parameterized query to prevent SQL Injection
  const sql = "INSERT INTO orders (fullname, email, item, message) VALUES (?, ?, ?, ?)";
  db.query(sql, [fullname.trim(), email.trim(), item.trim(), message.trim()], (err) => {
    if (err) {
      console.error("❌ Error inserting data:", err);
      return res.status(500).json({ message: "Database error" });
    }
    res.json({ message: "✅ Order placed securely!" });
  });
});
*/

// ==========================================================
// --- Stored XSS Guestbook (VULNERABLE) with attack logging ---
app.post("/comment", (req, res) => {
  let { name = "", comment = "" } = req.body || {};

  // defensive: ensure strings to avoid crash, but keep intentionally vulnerable processing
  name = String(name);
  comment = String(comment);

  // Prevent SQL string syntax errors by doubling single quotes (still vulnerable to injection)
  const nameEsc = name.replace(/'/g, "''");
  const commentEsc = comment.replace(/'/g, "''");

  const sql = `INSERT INTO comments (name, comment) VALUES ('${nameEsc}', '${commentEsc}')`;

  console.log("💉 Executing vulnerable SQL:", sql);

  // Log the incoming comment attempt (always)
  logAttack({
    type: "comment_submit",
    ip: req.ip,
    ua: req.get("User-Agent"),
    name: name,
    preview: comment.slice(0, 200),
    url: req.originalUrl,
  });

  // Detect suspicious patterns (basic heuristics for demo)
  const lower = (name + " " + comment).toLowerCase();
  const xssIndicators = [
    "<script",
    "onerror",
    "onload",
    "document.cookie",
    "innerhtml",
    "<svg",
    "<iframe",
    "javascript:",
  ];
  const sqliIndicators = [
    "' or '1'='1",
    "or 1=1",
    "union select",
    "information_schema",
    "drop table",
    "-- ",
  ];

  if (xssIndicators.some((p) => lower.includes(p))) {
    logAttack({
      type: "stored_xss_detected",
      note: "Comment contains likely XSS payload",
      ip: req.ip,
      ua: req.get("User-Agent"),
      name: name,
      preview: comment.slice(0, 500),
      url: req.originalUrl,
    });
  }
  if (sqliIndicators.some((p) => lower.includes(p))) {
    logAttack({
      type: "possible_sql_injection_in_comment",
      ip: req.ip,
      ua: req.get("User-Agent"),
      name: name,
      preview: comment.slice(0, 500),
      url: req.originalUrl,
    });
  }

  db.query(sql, (err, result) => {
    if (err) {
      console.error("❌ SQL Error:", err);
      logAttack({
        type: "sql_error",
        note: err && err.sqlMessage ? err.sqlMessage : String(err),
        ip: req.ip,
        ua: req.get("User-Agent"),
        url: req.originalUrl,
      });
      return res.status(500).send("Error saving comment");
    }

    // success
    logAttack({
      type: "comment_saved",
      ip: req.ip,
      ua: req.get("User-Agent"),
      id: result.insertId || null,
      name,
      url: req.originalUrl,
    });

    res.json({ ok: true });
  });
});

app.get("/guestbook", (req, res) => {
  const filter = req.query.search || "";
  const sql = `SELECT name, comment FROM comments WHERE name LIKE '%${filter}%' ORDER BY id DESC`;

  console.log("💉 Guestbook query:", sql);

  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send("Error fetching comments");

    let html = `
      <h1>Guestbook</h1>
      <a href="/">Back</a>
      <form method="GET" action="/guestbook" style="margin-bottom:1rem;">
        <input name="search" placeholder="Search by name (SQLi test)" value="${filter}" />
        <button type="submit">Search</button>
      </form>
    `;

    rows.forEach((r) => {
      html += `<div><strong>${r.name}</strong>: ${r.comment}</div>`;
    });

    res.send(html);
  });
});

/*
 // --- Stored XSS Guestbook (SANITIZED EXAMPLE) ---
const escapeHtml = (s) => s.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));

app.get("/guestbook", (req, res) => {
  db.query("SELECT name, comment FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).send("Error fetching comments");

    let html = `<h1>Guestbook (Sanitized)</h1><a href="/">Back</a>`;
    rows.forEach((r) => {
      html += `<div><strong>${escapeHtml(r.name)}</strong>: ${escapeHtml(r.comment)}</div>`;
    });
    res.send(html);
  });
});
*/

// ==========================================================
// --- Brute Force Login (VULNERABLE) ---
const testUser = { username: "testuser", password: "password123" };
app.post("/login", (req, res) => {
  const { username = '', password = '' } = req.body || {};

  // Basic input type normalization
  const userInput = String(username);
  const passInput = String(password);

  // Log the attempt
  logAttack({
    type: 'login_attempt',
    ip: req.ip,
    ua: req.get('User-Agent'),
    username: userInput,
    url: req.originalUrl
  });

  const injPatterns = ["'", '"', " or ", " OR ", "1=1", "union", "--", ";"];
  if (injPatterns.some(p => userInput.toLowerCase().includes(p) || passInput.toLowerCase().includes(p))) {
    logAttack({
      type: 'possible_login_injection',
      note: 'Suspicious characters in username/password',
      ip: req.ip,
      ua: req.get('User-Agent'),
      username: userInput,
      url: req.originalUrl
    });
  }

  const sql = "SELECT username, password, is_hashed FROM admin WHERE username = ?";
  db.query(sql, [userInput], (err, results) => {
    if (err) {
      console.error('DB error during login:', err);
      logAttack({ type: 'login_db_error', error: err.message, ip: req.ip, username: userInput });
      return res.status(500).json({ message: 'Database error' });
    }

    if (!results || results.length === 0) {
      logAttack({ type: 'login_failed', reason: 'no_such_user', ip: req.ip, username: userInput });
      return res.status(401).send(`
        <h1>❌ Invalid credentials</h1>
        <p>Login failed for: <strong>${userInput}</strong></p>
        <p><a href="/login.html">Try again</a></p>
      `);
    }

    const user = results[0];

    if (user.is_hashed) {
      if (bcrypt.compareSync(passInput, user.password)) {
        logAttack({ type: 'login_success', username: user.username, method: 'bcrypt', ip: req.ip, ua: req.get('User-Agent') });
        return res.json({ success: true, message: `✅ Welcome, ${user.username}!` });
      } else {
        logAttack({ type: 'login_failed', reason: 'bad_password', username: user.username, ip: req.ip });
        return res.status(401).send(`
          <h1>❌ Invalid credentials</h1>
          <p>Login failed for: <strong>${userInput}</strong></p>
          <p><a href="/login.html">Try again</a></p>
        `);
      }
    } else {
      if (passInput === user.password) {
        logAttack({ type: 'login_success', username: user.username, method: 'plaintext', ip: req.ip, ua: req.get('User-Agent') });
        return res.json({ success: true, message: `✅ Welcome, ${user.username}!` });
      } else {
        logAttack({ type: 'login_failed', reason: 'bad_password', username: user.username, ip: req.ip });
        return res.status(401).send(`
          <h1>❌ Invalid credentials</h1>
          <p>Login failed for: <strong>${userInput}</strong></p>
          <p><a href="/login.html">Try again</a></p>
        `);
      }
    }
  });
});
/*
 // --- Brute Force Login (SANITIZED EXAMPLE) ---
const loginLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 5, message: "Too many login attempts" });
app.use("/login", loginLimiter);

const hashedPassword = bcrypt.hashSync("password123", 10); 

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === "testuser" && bcrypt.compareSync(password, hashedPassword)) {
    return res.json({ success: true, message: "✅ Logged in securely" });
  }
  return res.status(401).json({ success: false, message: "❌ Invalid credentials" });
});
*/

// ==========================================================
// --- Honeypot endpoint (Detection feature, safe) ---
const decoys = ["/admin", "/backup.zip", "/.env", "/wp-login.php"];
app.use((req, res, next) => {
  if (decoys.includes(req.path)) {
    const log = {
      ts: new Date().toISOString(),
      ip: req.ip,
      ua: req.get("User-Agent"),
      url: req.originalUrl,
      headers: req.headers,
    };
    fs.appendFileSync("honeypot.log", JSON.stringify(log) + "\n");
    return res.status(404).send("Not Found");
  }
  next();
});

// ==========================================================
// --- Vulnerable Search (SQL Injection Demo) ---
app.get("/vuln-search", (req, res) => {
  const q = req.query.q || "";
  const sql = `SELECT id, fullname, email, item, message FROM orders WHERE fullname LIKE '%${q}%' OR email LIKE '%${q}%'`;

  console.log("💉 Executing vulnerable query:", sql);

  const attackLogPath = path.join(__dirname, "..", "attack.log");
  const lowerQ = q.toLowerCase();
  const sqliPatterns = [
    "' or '1'='1",
    "or 1=1",
    "union select",
    "information_schema",
    "drop table",
  ];
  if (sqliPatterns.some((p) => lowerQ.includes(p))) {
    const entry = {
      ts: new Date().toISOString(),
      ip: req.ip,
      ua: req.get("User-Agent"),
      query: q,
      url: req.originalUrl,
      note: "Possible SQL Injection Attempt",
      type: "sql_injection_detected",
    };
    fs.appendFileSync(attackLogPath, JSON.stringify(entry) + "\n");
    logAttack(Object.assign({ type: "sql_injection_detected" }, entry));
  }

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows);
  });
});

/*
 // --- Safe Search (SANITIZED EXAMPLE) ---
app.get("/safe-search", (req, res) => {
  const q = req.query.q || "";
  const sql = "SELECT id, fullname, email, item, message FROM orders WHERE fullname LIKE ? OR email LIKE ?";
  db.query(sql, [`%${q}%`, `%${q}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: "Database error" });
    res.json(rows);
  });
});
*/

// ==========================================================
// --- CSP Reporting (safe) ---
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy-Report-Only",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; report-uri /csp-report"
  );
  next();
});

app.post(
  "/csp-report",
  express.text({
    type: ["application/csp-report", "application/json", "text/plain", "*/*"],
    limit: "64kb",
  }),
  (req, res) => {
    let payload = req.body;
    let parsed = null;
    try {
      parsed = typeof payload === "string" ? JSON.parse(payload) : payload;
    } catch {
      parsed = { raw: payload };
    }

    if (parsed && parsed["csp-report"]) parsed = parsed["csp-report"];

    const entry = {
      ts: new Date().toISOString(),
      ip: req.ip,
      headers: { "user-agent": req.get("User-Agent") },
      report: parsed,
    };
    fs.appendFileSync(cspLogPath, JSON.stringify(entry) + "\n");
    res.status(204).end();
  }
);

// ==========================================================
// --- Phishing simulation endpoints ---
const phishLogPath = path.join(__dirname, "..", "phish.log");
app.get("/phish-landing", (req, res) => {
  const record = {
    ts: new Date().toISOString(),
    ip: req.ip,
    ua: req.get("User-Agent"),
    referer: req.get("Referer") || null,
    q: req.query.q || null,
    url: req.originalUrl,
  };
  fs.appendFileSync(phishLogPath, JSON.stringify(record) + "\n");
  res.sendFile(path.join(__dirname, "..", "public", "phish-landing.html"));
});

app.get("/phish-stats", (req, res) => {
  let lines = [];
  try {
    const raw = fs.readFileSync(phishLogPath, "utf8").trim();
    if (raw) lines = raw.split("\n").map((l) => JSON.parse(l));
  } catch {}
  let html = `<h1>Phish Clicks (local demo)</h1><p>Total clicks: ${lines.length}</p>`;
  html += `<table border="1" cellpadding="6" style="border-collapse:collapse"><thead><tr><th>#</th><th>timestamp</th><th>q (test id)</th><th>ip</th><th>user-agent</th><th>referer</th></tr></thead><tbody>`;
  lines.reverse().forEach((r, i) => {
    html += `<tr><td>${i + 1}</td><td>${r.ts}</td><td>${r.q || ""}</td><td>${
      r.ip
    }</td><td>${r.ua}</td><td>${r.referer || ""}</td></tr>`;
  });
  html += `</tbody></table><p><small>Note: demo only — do not expose externally.</small></p>`;
  res.send(html);
});

// ==========================================================
const PORT = 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
