const jwt = require('jsonwebtoken');

// Real token check: returns the verified subject, or null.
async function verifyToken(header) {
  if (!header) return null;
  try {
    return jwt.verify(header.replace('Bearer ', ''), process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

module.exports = { verifyToken };
