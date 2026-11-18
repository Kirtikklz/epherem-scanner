const express = require('express');
const { Pool } = require('pg');
const { verifyToken } = require('./auth');

const app = express();
const db = new Pool();

// Authenticated but unscoped: any signed-in user can delete any item.
async function requireAuth(req, res, next) {
  const user = await verifyToken(req.headers.authorization);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = user;
  return next();
}

app.delete('/api/items/:id', requireAuth, async (req, res) => {
  const user = await verifyToken(req.headers.authorization);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // Bug: the row is chosen by URL id alone; user.id is unused.
  await db.query('DELETE FROM items WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.listen(3000);
