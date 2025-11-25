const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS for Render + local
app.use(cors({
  origin: [
    "http://localhost:3000",
    "https://business-dashboard-pro.onrender.com"
  ],
  credentials: true
}));

app.use(express.json());

// Serve static files from the SAME folder server.js lives in
app.use(express.static(__dirname));

app.use(
  session({
    secret: "CHANGE_THIS_TO_A_LONG_RANDOM_STRING",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60
    }
  })
);

// MySQL connection
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10
});
const promisePool = pool.promise();

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  next();
}

// AUTH ROUTES
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const [check] = await promisePool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (check.length) return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    await promisePool.query(
      "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
      [full_name, email, hash]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await promisePool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (!rows.length) return res.status(401).json({ error: "Invalid email or password" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });

    req.session.userId = user.user_id;
    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

// BUSINESS ENDPOINTS (trimmed for space but still included)
app.get('/api/sales/monthly', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const year = req.query.year || new Date().getFullYear();
  const [rows] = await promisePool.query(
    "SELECT month_name, sales_amount, month FROM monthly_sales WHERE user_id = ? AND year = ? ORDER BY month",
    [userId, year]
  );
  res.json(rows);
});

app.get('/api/metrics/latest', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const [rows] = await promisePool.query(
    "SELECT * FROM business_metrics WHERE user_id = ? ORDER BY metric_date DESC LIMIT 1",
    [userId]
  );
  res.json(rows[0] || {});
});

// FALLBACK FOR RENDER
// Serve index.html for unknown paths EXCEPT when requesting a file
app.get(/^\/(?!.*\.).*$/, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
