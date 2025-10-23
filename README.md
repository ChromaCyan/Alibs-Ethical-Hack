# 🥙 Alibaba Shawarma 

A simple employment website built with **HTML**, **CSS**, and **Node.js (Express)** that connects to a **MySQL** database using **XAMPP**.  
This project is designed as a **dummy company website** for ethical hacking practice — where students can safely perform penetration testing on a locally hosted environment.

---

## 🚀 Features

What this project contains (high level)

- Frontend: static HTML/CSS/vanilla JS (Alibaba Shawarma theme)

- Backend: Node.js + Express

- Database: MySQL (XAMPP recommended for local)

**Example vulnerable endpoints for lab exercises:**

- /submit — create an order (table orders)

- /vuln-search — intentionally vulnerable search (SQLi lab)

- /comment and /guestbook — stored XSS lab

- /login — simple test user for brute-force exercise

- /upload — file upload test (stores files to uploads/)

- /phish-landing, /phish-beacon, /phish-stats — phishing demo (harmless)

- /csp-report — Content-Security-Policy reporting endpoint

honeypot decoys (e.g. /admin, /get-data) — logs to honeypot.log
---

## Important Notice

1. Only run tests on this local instance / isolated VM you control.
2. For phishing simulations, use opt-in test accounts only and never collect real credentials or PII. Landing pages must be benign.
3. Keep logs local and do not expose diagnostic endpoints publicly.
4. Make sure you have the following installed:

## 🛠️ Requirements

- [Node.js](https://nodejs.org/) (v18 or higher)
- [XAMPP](https://www.apachefriends.org/)
- MySQL Database (through XAMPP)
- A text editor like VS Code

---

## ⚙️ Setup Instructions

### 1. Clone the repository

```bash
git clone https://github.com/ChromaCyan/Alibs-Ethical-Hack.git
cd EHL

### 2. Install Dependencies

```bash

npm install

### 3. Create Database in phpmyadmin
```bash

CREATE DATABASE ehl_careers;
USE ehl_careers;

-- orders table (demo orders)
CREATE TABLE orders (
  id INT AUTO_INCREMENT PRIMARY KEY,
  fullname VARCHAR(255),
  email VARCHAR(255),
  item VARCHAR(255),
  message TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- comments table (guestbook XSS)
CREATE TABLE comments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255),
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- uploads table
CREATE TABLE uploads (
  id INT AUTO_INCREMENT PRIMARY KEY,
  filename VARCHAR(255),
  original VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- applications (if you kept original)
CREATE TABLE applications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  fullname VARCHAR(255),
  email VARCHAR(255),
  position VARCHAR(255),
  message TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- lab_users for brute force lab (optional)
CREATE TABLE lab_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) UNIQUE,
  password VARCHAR(255), -- store hashed in production demo
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- seed a test user (plain text for lab only)
INSERT INTO lab_users (username, password) VALUES ('testuser','password123');


### 4. Run the App
```bash

node server/server.js