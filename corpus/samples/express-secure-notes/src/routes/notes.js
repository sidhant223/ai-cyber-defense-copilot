const express = require('express');
const { z } = require('zod');

const pool = require('../db');
const { requireAuth, validate } = require('../middleware');

const router = express.Router();

router.use(requireAuth);

const noteSchema = z.object({
  title: z.string().min(1).max(200),
  body: z.string().max(20000),
});

const searchSchema = z.object({
  q: z.string().max(100),
});

router.get('/', requireAuth, async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, title, body FROM notes WHERE user_id = ?',
    [req.session.userId]
  );
  res.json(rows);
});

router.get('/search', requireAuth, validate(searchSchema, 'query'), async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, title FROM notes WHERE user_id = ? AND title LIKE CONCAT("%", ?, "%")',
    [req.session.userId, req.validated.q]
  );
  res.json(rows);
});

router.post('/', requireAuth, validate(noteSchema, 'body'), async (req, res) => {
  const { title, body } = req.validated;
  const [result] = await pool.query(
    'INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)',
    [req.session.userId, title, body]
  );
  res.status(201).json({ id: result.insertId });
});

router.put('/:id', requireAuth, validate(noteSchema, 'body'), async (req, res) => {
  const { title, body } = req.validated;
  await pool.query(
    'UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?',
    [title, body, req.params.id, req.session.userId]
  );
  res.json({ status: 'updated' });
});

router.delete('/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM notes WHERE id = ? AND user_id = ?', [
    req.params.id,
    req.session.userId,
  ]);
  res.json({ status: 'deleted' });
});

module.exports = router;
