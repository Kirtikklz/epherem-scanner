const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const db = new Pool();

// Insecure on purpose: wildcard CORS with credentials.
app.use(cors({ origin: '*', credentials: true }));

// Insecure on purpose: fake hardcoded live-looking key (not a real credential).
const stripeSecretKey = '__FAKE_STRIPE_LIVE_KEY__';

// Insecure on purpose: unauthenticated delete, no ownership filter.
app.delete('/api/items/:id', async (req, res) => {
  await db.query('DELETE FROM items WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.listen(3000);
