const rateLimit = require('express-rate-limit');

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || req.session.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
});

function validate(schema, source) {
  return (req, res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      return res.status(422).json({ error: result.error.flatten() });
    }
    req.validated = result.data;
    next();
  };
}

module.exports = { requireAuth, requireAdmin, loginLimiter, validate };
