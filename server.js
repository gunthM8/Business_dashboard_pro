const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://business-dashboard-pro.onrender.com',
    'https://bizdashboardpro.com'
  ],
  credentials: true
}));

app.use(express.json());

// Serve static files FROM ROOT (important!)
app.use(express.static(__dirname));

app.use(session({
  secret: 'CHANGE_THIS_TO_A_LONG_RANDOM_STRING',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60
  }
}));

// MySQL
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

// Middleware
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
      return res.status(400).json({ error: 'Email and password required' });

    const [existing] = await promisePool.query(
      'SELECT * FROM users WHERE email = ?', [email]
    );

    if (existing.length)
      return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);

    await promisePool.query(
      'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
      [full_name, email, hash]
    );

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});


app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await promisePool.query(
      'SELECT * FROM users WHERE email = ?', [email]
    );

    if (!rows.length) return res.status(401).json({ error: "Invalid email or password" });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });

    req.session.userId = rows[0].user_id;

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ success: true });
  });
});


//OTHER API ROUTES


// FALLBACK ROUTE — serve index.html only for unknown paths
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
