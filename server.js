const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

   //CORS (Allow Render + local dev)
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://business-dashboard-pro.onrender.com'
  ],
  credentials: true
}));

app.use(express.json());

   //Serve STATIC FILES correctly (IMPORTANT for Render)
app.use(express.static(path.join(__dirname)));

app.use(
  session({
    secret: 'CHANGE_THIS_TO_A_LONG_RANDOM_STRING',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 // 1 hour
    }
  })
);

  // MYSQL (Railway / PlanetScale / Render)
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

   //Authentication Middleware
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

  // AUTH ROUTES
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const [user] = await promisePool.query(
      'SELECT * FROM users WHERE email = ?', [email]
    );

    if (user.length > 0)
      return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);

    await promisePool.query(
      'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
      [full_name, email, hash]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [user] = await promisePool.query(
      'SELECT * FROM users WHERE email = ?', [email]
    );

    if (user.length === 0)
      return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user[0].password_hash);
    if (!valid)
      return res.status(401).json({ error: 'Invalid email or password' });

    req.session.userId = user[0].user_id;
    req.session.userEmail = user[0].email;

    res.json({ success: true });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});

  // BUSINESS DASHBOARD API ROUTES

app.get('/api/sales/monthly', requireLogin, async (req, res) => {
  const userId = req.session.userId;
  const year = req.query.year || new Date().getFullYear();

  try {
    const [rows] = await promisePool.query(
      `SELECT month_name, sales_amount, month
       FROM monthly_sales
       WHERE user_id = ? AND year = ?
       ORDER BY month`,
      [userId, year]
    );

    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch monthly sales' });
  }
});

app.get('/api/metrics/latest', requireLogin, async (req, res) => {
  const userId = req.session.userId;

  try {
    const [rows] = await promisePool.query(
      `SELECT * FROM business_metrics
       WHERE user_id = ?
       ORDER BY metric_date DESC
       LIMIT 1`,
      [userId]
    );
    res.json(rows[0] || {});
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch metrics' });
  }
});

app.post('/api/metrics', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { metric_date, total_sales, total_expenses, net_profit } = req.body;

    await promisePool.query(
      `INSERT INTO business_metrics (user_id, metric_date, total_sales, total_expenses, net_profit)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE 
         total_sales = VALUES(total_sales),
         total_expenses = VALUES(total_expenses),
         net_profit = VALUES(net_profit)`,
      [userId, metric_date, total_sales, total_expenses, net_profit]
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update metrics' });
  }
});

// Serve static files (HTML, CSS, JS)
app.use(express.static(__dirname));

// Fallback route ONLY for non-file paths
app.get(/^\/(?!.*\.).*$/, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// START SERVER
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
