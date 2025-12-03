require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS – allow all front-end URLs
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://business-dashboard-pro.onrender.com',
    'https://bizdashboardpro.com',
    'https://www.bizdashboardpro.com',
    'businessdashboardpro-production.up.railway.app'
  ],
  credentials: true
}));

app.use(express.json());


// Session cookies
app.use(
  session({
    secret: process.env.SESSION_SECRET || "AjnjabiibnijbAiNUHInIBi",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60
    }
  })
);

// MYSQL (Railway)
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT || 3306,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10
});
const promisePool = pool.promise();

// Test database connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
  } else {
    console.log('Database connected successfully');
    connection.release();
  }
});

// LOGIN REQUIRED middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  next();
}

// AUTH ROUTES
app.post("/api/register", async (req, res) => {
  try {
    const { full_name, email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const [existing] = await promisePool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existing.length > 0)
      return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);

    await promisePool.query(
      "INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)",
      [full_name, email, hash]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await promisePool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (rows.length === 0)
      return res.status(401).json({ error: "Invalid email or password" });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid)
      return res.status(401).json({ error: "Invalid email or password" });

    req.session.userId = rows[0].user_id;
    res.json({ success: true });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

// TRANSACTION ROUTES 
app.get("/api/transactions", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const { search, type, start_date, end_date, limit, id } = req.query;

  try {
    let query = "SELECT * FROM transactions WHERE user_id = ?";
    const params = [userId];

    if (id) {
      query += " AND transaction_id = ?";
      params.push(id);
    }

    if (search) {
      query += " AND (description LIKE ? OR category LIKE ? OR notes LIKE ?)";
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }

    if (type) {
      query += " AND transaction_type = ?";
      params.push(type);
    }

    if (start_date) {
      query += " AND transaction_date >= ?";
      params.push(start_date);
    }

    if (end_date) {
      query += " AND transaction_date <= ?";
      params.push(end_date);
    }

    query += " ORDER BY transaction_date DESC";

    if (limit) {
      query += " LIMIT ?";
      params.push(parseInt(limit));
    }

    const [rows] = await promisePool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error("Get transactions error:", err);
    res.status(500).json({ error: "Failed to fetch transactions" });
  }
});

app.post("/api/transactions", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const { transaction_date, description, amount, transaction_type, category, notes } = req.body;

  try {
    const [result] = await promisePool.query(
      "INSERT INTO transactions (user_id, transaction_date, description, amount, transaction_type, category, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [userId, transaction_date, description, amount, transaction_type, category, notes]
    );

    res.json({ success: true, transaction_id: result.insertId });
  } catch (err) {
    console.error("Create transaction error:", err);
    res.status(500).json({ error: "Failed to create transaction" });
  }
});

app.put("/api/transactions/:id", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const transactionId = req.params.id;
  const { transaction_date, description, amount, transaction_type, category, notes } = req.body;

  try {
    const [result] = await promisePool.query(
      "UPDATE transactions SET transaction_date = ?, description = ?, amount = ?, transaction_type = ?, category = ?, notes = ? WHERE transaction_id = ? AND user_id = ?",
      [transaction_date, description, amount, transaction_type, category, notes, transactionId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Update transaction error:", err);
    res.status(500).json({ error: "Failed to update transaction" });
  }
});

app.get("/api/transactions/totals", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const days = req.query.days || 30;

  try {
    const [rows] = await promisePool.query(
      `SELECT 
        SUM(CASE WHEN transaction_type = 'Income' THEN amount ELSE 0 END) as total_sales,
        SUM(CASE WHEN transaction_type = 'Expense' THEN amount ELSE 0 END) as total_expenses,
        SUM(CASE WHEN transaction_type = 'Income' THEN amount ELSE -amount END) as net_profit
      FROM transactions 
      WHERE user_id = ? AND transaction_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)`,
      [userId, days]
    );

    res.json(rows[0] || { total_sales: 0, total_expenses: 0, net_profit: 0 });
  } catch (err) {
    console.error("Get totals error:", err);
    res.status(500).json({ error: "Failed to fetch totals" });
  }
});

app.get("/api/transactions/recent", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const limit = req.query.limit || 10;

  try {
    const [rows] = await promisePool.query(
      "SELECT * FROM transactions WHERE user_id = ? ORDER BY transaction_date DESC LIMIT ?",
      [userId, parseInt(limit)]
    );
    res.json(rows);
  } catch (err) {
    console.error("Get recent transactions error:", err);
    res.status(500).json({ error: "Failed to fetch recent transactions" });
  }
});

// METRICS & SALES ROUTES 
app.get("/api/sales/monthly", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const year = req.query.year || new Date().getFullYear();

  try {
    const [rows] = await promisePool.query(
      "SELECT month_name, sales_amount, month FROM monthly_sales WHERE user_id = ? AND year = ? ORDER BY month",
      [userId, year]
    );
    res.json(rows);
  } catch (err) {
    console.error("Get monthly sales error:", err);
    res.status(500).json({ error: "Failed to fetch monthly sales" });
  }
});

app.get("/api/metrics/latest", requireLogin, async (req, res) => {
  const userId = req.session.userId;
  try {
    const [rows] = await promisePool.query(
      "SELECT * FROM business_metrics WHERE user_id = ? ORDER BY metric_date DESC LIMIT 1",
      [userId]
    );
    res.json(rows[0] || {});
  } catch (err) {
    console.error("Get metrics error:", err);
    res.status(500).json({ error: "Failed to fetch metrics" });
  }
});

// Serve STATIC website content
app.use(express.static(path.join(__dirname)));
app.use(express.static(path.join(__dirname, "public")));

// FALLBACK ROUTE (SAFE)
// ONLY serves index.html when no real file exists.
app.get("*", (req, res) => {
  if (req.path.startsWith("/api")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "index.html"));
});


// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
