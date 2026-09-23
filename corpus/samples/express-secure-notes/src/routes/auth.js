const express = require('express');
const bcrypt = require('bcrypt');
const { z } = require('zod');

const pool = require('../db');
const { loginLimiter, validate } = require('../middleware');

const router = express.Router();

const credentialsSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(12).max(128),
});

router.post('/register', loginLimiter, validate(credentialsSchema, 'body'), async (req, res) => {
  const { email, password } = req.validated;
  const hash = await bcrypt.hash(password, 12);
  const [result] = await pool.query(
    'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
    [email, hash, 'user']
  );
  res.status(201).json({ id: result.insertId });
});

router.post('/login', loginLimiter, validate(credentialsSchema, 'body'), async (req, res) => {
  const { email, password } = req.validated;
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'internal error' });
    req.session.userId = user.id;
    req.session.role = user.role;
    res.json({ status: 'ok' });
  });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ status: 'ok' }));
});

module.exports = router;
