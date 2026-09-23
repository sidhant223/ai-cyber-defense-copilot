const express = require('express');
const { pool } = require('../server');

const router = express.Router();

router.get('/customers', async (req, res) => {
  const [rows] = await pool.query('SELECT id, name, email, plan FROM customers');
  res.json(rows);
});

router.get('/customers/search', async (req, res) => {
  const term = req.query.q;
  const [rows] = await pool.query(
    `SELECT id, name, email FROM customers WHERE name LIKE '%${term}%'`
  );
  res.json(rows);
});

router.get('/customers/:id', async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM customers WHERE id = ?', [req.params.id]);
  res.json(rows[0]);
});

router.put('/customers/:id/plan', async (req, res) => {
  const { plan } = req.body;
  await pool.query('UPDATE customers SET plan = ? WHERE id = ?', [plan, req.params.id]);
  res.json({ status: 'updated' });
});

router.post('/customers/:id/suspend', async (req, res) => {
  await pool.query('UPDATE customers SET suspended = 1 WHERE id = ?', [req.params.id]);
  res.json({ status: 'suspended' });
});

router.get('/export', async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM customers');
  const csv = rows.map((r) => Object.values(r).join(',')).join('\n');
  res.type('text/csv').send(csv);
});

router.put('/settings/email-template', async (req, res) => {
  const { template } = req.body;
  await pool.query('UPDATE settings SET email_template = ? WHERE id = 1', [template]);
  res.json({ status: 'saved' });
});

module.exports = router;
