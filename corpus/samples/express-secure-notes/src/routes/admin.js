const express = require('express');

const pool = require('../db');
const { requireAuth, requireAdmin } = require('../middleware');

const router = express.Router();

router.use(requireAuth, requireAdmin);

router.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT id, email, role FROM users');
  res.json(rows);
});

router.delete('/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ status: 'deleted' });
});

module.exports = router;
