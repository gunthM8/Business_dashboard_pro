const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://business-dashboard-pro.onrender.com'
  ],
  credentials: true
}));


app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: 'CHANGE_THIS_TO_A_LONG_RANDOM_STRING',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 
    }
  })
);

// MySQL Connection Pool (Render + Railway)
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  port: process.env.MYSQL_PORT,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const promisePool = pool.promise();


// Auth Protection
function requireLogin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

//Register User
app.post('/api/register', async (req, res) => {
  try {
    const { full_name, email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const [existing] = await promisePool.query(
      'SELECT user_id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const [result] = await promisePool.query(
      'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
      [full_name || null, email, password_hash]
    );

    res.status(201).json({ success: true, message: 'Account created successfully' });

  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

//User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await promisePool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = rows[0];
    const correct = await bcrypt.compare(password, user.password_hash);

    if (!correct) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    req.session.userId = user.user_id;
    req.session.userEmail = user.email;
    req.session.userName = user.full_name;

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        user_id: user.user_id,
        full_name: user.full_name,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// User Logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

//Monthly Sales
app.get('/api/sales/monthly', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const year = req.query.year || new Date().getFullYear();

    const [rows] = await promisePool.query(
      `SELECT month_name, sales_amount, month
         FROM monthly_sales
        WHERE user_id = ? AND year = ?
        ORDER BY month`,
      [userId, year]
    );

    res.json(rows);
  } catch (error) {
    console.error('Monthly sales error:', error);
    res.status(500).json({ error: 'Failed to fetch monthly sales' });
  }
});

// Latest Business Metrics
app.get('/api/metrics/latest', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;

    const [rows] = await promisePool.query(
      `SELECT * FROM business_metrics
        WHERE user_id = ?
        ORDER BY metric_date DESC
        LIMIT 1`,
      [userId]
    );

    res.json(rows[0] || {});
  } catch (error) {
    console.error('Metrics latest error:', error);
    res.status(500).json({ error: 'Failed to fetch metrics' });
  }
});

// Insert/Update Metrics
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

    res.json({ success: true, message: 'Metrics saved' });

  } catch (error) {
    console.error('Metrics update error:', error);
    res.status(500).json({ error: 'Failed to update metrics' });
  }
});

//Get All Transactions (with filters)
app.get('/api/transactions', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { search, type, start_date, end_date } = req.query;

    let sql = `
      SELECT * FROM transactions
      WHERE user_id = ?
    `;
    const params = [userId];

    if (type) {
      sql += ' AND transaction_type = ?';
      params.push(type);
    }

    if (start_date) {
      sql += ' AND transaction_date >= ?';
      params.push(start_date);
    }

    if (end_date) {
      sql += ' AND transaction_date <= ?';
      params.push(end_date);
    }

    if (search) {
      const like = `%${search}%`;
      sql += ` AND (description LIKE ? OR category LIKE ? OR notes LIKE ?)`;
      params.push(like, like, like);
    }

    sql += ' ORDER BY transaction_date DESC';

    const [rows] = await promisePool.query(sql, params);

    res.json(rows);
  } catch (error) {
    console.error('Fetch transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

//Get Recent Transactions 
app.get('/api/transactions/recent', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const limit = parseInt(req.query.limit || '10', 10);

    const [rows] = await promisePool.query(
      `SELECT * FROM transactions
        WHERE user_id = ?
        ORDER BY transaction_date DESC
        LIMIT ?`,
      [userId, limit]
    );

    res.json(rows);
  } catch (error) {
    console.error('Recent transactions error:', error);
    res.status(500).json({ error: 'Failed to fetch recent transactions' });
  }
});

// Add Transaction
app.post('/api/transactions', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { transaction_date, description, amount, transaction_type, category, notes } = req.body;

    const [result] = await promisePool.query(
      `INSERT INTO transactions (transaction_date, description, amount, transaction_type, category, notes, user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [transaction_date, description, amount, transaction_type, category, notes, userId]
    );

    res.json({ success: true, transaction_id: result.insertId });
  } catch (error) {
    console.error('Add transaction error:', error);
    res.status(500).json({ error: 'Failed to add transaction' });
  }
});

// Delete Transaction
app.delete('/api/transactions/:id', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { id } = req.params;

    const [result] = await promisePool.query(
      `DELETE FROM transactions
        WHERE transaction_id = ? AND user_id = ?`,
      [id, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json({ success: true, message: 'Transaction deleted' });

  } catch (error) {
    console.error('Delete transaction error:', error);
    res.status(500).json({ error: 'Failed to delete transaction' });
  }
});

//Totals
app.get('/api/transactions/totals', requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const days = parseInt(req.query.days || '30', 10);

    const [rows] = await promisePool.query(
      `SELECT 
         SUM(CASE WHEN transaction_type = 'Income' THEN amount ELSE 0 END) as total_sales,
         SUM(CASE WHEN transaction_type = 'Expense' THEN amount ELSE 0 END) as total_expenses,
         SUM(CASE WHEN transaction_type = 'Income' THEN amount ELSE -amount END) as net_profit
       FROM transactions
       WHERE user_id = ?
         AND transaction_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)`,
      [userId, days]
    );

    res.json(rows[0]);
  } catch (error) {
    console.error('Totals error:', error);
    res.status(500).json({ error: 'Failed to fetch totals' });
  }
});

app.get("/:page", (req, res) => {
  res.sendFile(path.join(__dirname, "public", req.params.page));
});

// START SERVER

app.listen(PORT, () => {
  console.log(`\n🚀 Server running at http://localhost:${PORT}`);
  console.log(`📡 API ready at http://localhost:${PORT}/api\n`);
});
