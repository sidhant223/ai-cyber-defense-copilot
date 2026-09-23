const express = require('express');
const jwt = require('jsonwebtoken');
const pool = require('../db');

const router = express.Router();

const JWT_SECRET = 'todoapp-jwt-signing-secret';

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

router.get('/', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM todos WHERE user_id = $1', [req.user.sub]);
  res.json(result.rows);
});

router.post('/', requireAuth, async (req, res) => {
  const { title, due } = req.body;
  const result = await pool.query(
    'INSERT INTO todos (user_id, title, due) VALUES ($1, $2, $3) RETURNING *',
    [req.user.sub, title, due]
  );
  res.status(201).json(result.rows[0]);
});

router.get('/search', async (req, res) => {
  const term = req.query.q;
  const result = await pool.query(`SELECT * FROM todos WHERE title ILIKE '%${term}%'`);
  res.json(result.rows);
});

router.put('/:id', async (req, res) => {
  const { title, done } = req.body;
  await pool.query('UPDATE todos SET title = $1, done = $2 WHERE id = $3', [
    title,
    done,
    req.params.id,
  ]);
  res.json({ status: 'updated' });
});

router.delete('/:id', async (req, res) => {
  await pool.query('DELETE FROM todos WHERE id = $1', [req.params.id]);
  res.json({ status: 'deleted' });
});

module.exports = router;
