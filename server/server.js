const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const multer = require("multer");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "../public")));

const cspLogPath = path.join(__dirname, '..', 'csp-reports.log');

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

// --- Serve index.html ---
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// --- Handle form submission ---
app.post("/submit", (req, res) => {
  const { fullname, email, item, message } = req.body; 

  if (!fullname || !email || !item || !message) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const sql = "INSERT INTO orders (fullname, email, item, message) VALUES (?, ?, ?, ?)";
  db.query(sql, [fullname, email, item, message], (err, result) => {
    if (err) {
      console.error("❌ Error inserting data:", err);
      return res.status(500).json({ message: "Database error" });
    }

    console.log(`✅ Order saved: ${fullname} (${item})`);
    res.json({ message: "Order placed successfully!" });
  });
});
// --- Stored XSS Guestbook ---
app.post("/comment", (req, res) => {
  const { name, comment } = req.body;
  const sql = "INSERT INTO comments (name, comment) VALUES (?, ?)";
  db.query(sql, [name, comment], (err, result) => {
    if (err) return res.status(500).send("Error saving comment");
    res.json({ ok: true });
  });
});

app.get("/guestbook", (req, res) => {
  db.query("SELECT name, comment FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).send("Error fetching comments");

    let html = `<h1>Guestbook</h1><a href="/">Back</a>`;
    rows.forEach((r) => {
      html += `<div><strong>${r.name}</strong>: ${r.comment}</div>`;
    });
    res.send(html);
  });
});

// --- Brute Force Login (for Hydra testing) ---
const testUser = { username: "testuser", password: "password123" };

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === testUser.username && password === testUser.password) {
    return res.json({ success: true, message: "✅ Logged in successfully" });
  }
  return res.status(401).json({ success: false, message: "❌ Invalid credentials" });
});

// --- File Upload (test file upload protections) ---
const upload = multer({ dest: "uploads/" });

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).send("No file uploaded");
  const sql = "INSERT INTO uploads (filename, original) VALUES (?, ?)";
  db.query(sql, [req.file.filename, req.file.originalname], (err) => {
    if (err) return res.status(500).send("Error saving upload");
    res.json({ message: `Uploaded ${req.file.originalname}` });
  });
});

// --- Honeypot endpoint (/admin) ---
const decoys = ['/admin', '/backup.zip', '/.env', '/wp-login.php'];
app.use((req,res,next)=>{
  if (decoys.includes(req.path)) {
    const log = { ts: new Date().toISOString(), ip: req.ip, ua: req.get('User-Agent'), url: req.originalUrl, headers: req.headers };
    fs.appendFileSync('honeypot.log', JSON.stringify(log) + '\n');
    return res.status(404).send('Not Found');
  }
  next();
});


app.get("/admin-dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/admin.html"));
});

app.get("/vuln-search", (req, res) => {
  const q = req.query.q || "";

  const sql = `SELECT id, fullname, email, item, message FROM orders WHERE fullname LIKE '%${q}%' OR email LIKE '%${q}%'`;

  console.log("💉 Executing vulnerable query:", sql);

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Database error" });
    }

    res.json(rows);
  });
});

app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy-Report-Only",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; report-uri /csp-report"
  );
  next();
});


app.post('/csp-report', express.text({ type: ['application/csp-report', 'application/json', 'text/plain', '*/*'], limit: '64kb' }), (req, res) => {
  console.log('CSP report headers:', req.headers['content-type']);

  let payload = req.body;
  let parsed = null;

  if (typeof payload === 'string' && payload.trim().length > 0) {
    try {
      parsed = JSON.parse(payload);
    } catch (err) {
      parsed = { raw: payload };
    }
  } else {
    parsed = payload;
  }

  if (parsed && parsed['csp-report']) parsed = parsed['csp-report'];

  const entry = {
    ts: new Date().toISOString(),
    ip: req.ip,
    headers: { 'user-agent': req.get('User-Agent') },
    report: parsed
  };

  try {
    fs.appendFileSync(cspLogPath, JSON.stringify(entry) + '\n');
  } catch (e) {
    console.error('Failed writing CSP report:', e);
  }

  console.log('Stored CSP report:', parsed);
  res.status(204).end();
});

const phishLogPath = path.join(__dirname, '..', 'phish.log'); 

app.get('/phish-landing', (req, res) => {
  const record = {
    ts: new Date().toISOString(),
    ip: req.ip,
    ua: req.get('User-Agent'),
    referer: req.get('Referer') || null,
    q: req.query.q || null,     
    url: req.originalUrl,
  };
  try {
    fs.appendFileSync(phishLogPath, JSON.stringify(record) + '\n');
  } catch (e) {
    console.error('Could not write phish log', e);
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'phish-landing.html'));
});

app.get('/phish-stats', (req, res) => {
  let lines = [];
  try {
    const raw = fs.readFileSync(phishLogPath, 'utf8').trim();
    if (raw) lines = raw.split('\n').map(l => JSON.parse(l));
  } catch (e) {
    lines = [];
  }
  let html = `<h1>Phish Clicks (local demo)</h1>`;
  html += `<p>Total clicks: ${lines.length}</p>`;
  html += `<table border="1" cellpadding="6" style="border-collapse:collapse"><thead><tr><th>#</th><th>timestamp</th><th>q (test id)</th><th>ip</th><th>user-agent</th><th>referer</th></tr></thead><tbody>`;
  lines.reverse().forEach((r, i) => {
    html += `<tr>
      <td>${i+1}</td>
      <td>${r.ts}</td>
      <td>${r.q || ''}</td>
      <td>${r.ip}</td>
      <td style="max-width:400px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.ua}</td>
      <td>${r.referer || ''}</td>
    </tr>`;
  });
  html += `</tbody></table>`;
  html += `<p><small>Note: this endpoint is for local demos only — do not expose to production.</small></p>`;
  res.send(html);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
