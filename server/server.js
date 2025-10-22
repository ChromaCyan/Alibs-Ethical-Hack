const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "../public")));

// --- MySQL connection ---
const db = mysql.createConnection({
  host: "localhost",
  user: "root", 
  database: "ehl_careers", //databaseName
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
  const { fullname, email, position, message } = req.body;

  if (!fullname || !email || !position || !message) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const sql = "INSERT INTO applications (fullname, email, position, message) VALUES (?, ?, ?, ?)";
  db.query(sql, [fullname, email, position, message], (err, result) => {
    if (err) {
      console.error("❌ Error inserting data:", err);
      return res.status(500).json({ message: "Database error" });
    }

    console.log(`✅ Application saved: ${fullname} (${position})`);
    res.json({ message: "Application submitted successfully!" });
  });
});


const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
