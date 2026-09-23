const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

const adminRoutes = require('./routes/admin');

const app = express();

const pool = mysql.createPool({
  host: 'db.internal',
  user: 'adminpanel',
  password: 'p4nel-Adm1n-2024',
  database: 'customers',
});

app.use(express.json());
app.use(
  session({
    secret: 'admin-panel-session-secret',
    resave: false,
    saveUninitialized: false,
  })
);

function requireLogin(req, res, next) {
  if (!req.session.staffId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await pool.query('SELECT * FROM staff WHERE email = ?', [email]);
  const staff = rows[0];
  if (!staff || !(await bcrypt.compare(password, staff.password_hash))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  req.session.staffId = staff.id;
  res.json({ status: 'ok' });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ status: 'ok' }));
});

app.use('/admin', requireLogin, adminRoutes);

app.listen(4000, () => console.log('admin panel on 4000'));

module.exports = { app, pool };
