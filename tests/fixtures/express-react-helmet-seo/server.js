const express = require('express');
const path = require('node:path');

const app = express();

app.use(express.static(path.join(__dirname, 'dist')));

app.get('/api/events', (req, res) => {
  res.json({ events: [] });
});

app.listen(3000);
