// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Low, JSONFile } = require('lowdb');
const { nanoid } = require('nanoid');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const DB_FILE = process.env.DB_FILE || 'db.json';
const OPENAI_KEY = process.env.OPENAI_API_KEY || null;

app.use(express.json());

// Allow your frontend origin (adjust if needed)
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5500',
  credentials: true
}));

// Initialize lowdb
const adapter = new JSONFile(DB_FILE);
const db = new Low(adapter);

async function initDB() {
  await db.read();
  db.data = db.data || { users: [], lawyers: [], cases: [], appointments: [] };

  // seed if empty
  if (db.data.lawyers.length === 0) {
    db.data.lawyers.push(
      { id: nanoid(), name: 'Atty. Maria Santos', specialty: 'Labor Law', rating: 4.8, experience: 5 },
      { id: nanoid(), name: 'Atty. Juan Cruz', specialty: 'Criminal Law', rating: 4.9, experience: 8 },
      { id: nanoid(), name: 'Atty. Ana Reyes', specialty: 'Family Law', rating: 4.7, experience: 6 }
    );
  }
  await db.write();
}
initDB();

// Simple middleware to auth JWT from Authorization header (Bearer) or cookie
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  let token = null;
  if (authHeader && authHeader.startsWith('Bearer ')) token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes ---

// Health
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, password, role = 'citizen' } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Missing fields' });

  await db.read();
  const exists = db.data.users.find(u => u.email === email.toLowerCase());
  if (exists) return res.status(409).json({ error: 'User already exists' });

  const pwHash = await bcrypt.hash(password, 10);
  const user = { id: nanoid(), name, email: email.toLowerCase(), password: pwHash, role, createdAt: new Date().toISOString() };
  db.data.users.push(user);
  await db.write();

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

  await db.read();
  const user = db.data.users.find(u => u.email === email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });

  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// Get current user
app.get('/api/me', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

// Get lawyers (public)
app.get('/api/lawyers', async (req, res) => {
  await db.read();
  res.json(db.data.lawyers || []);
});

// Get cases for a user (protected)
app.get('/api/cases', authMiddleware, async (req, res) => {
  await db.read();
  // simplistic: return all cases where userId matches or assigned lawyer matches
  const userCases = (db.data.cases || []).filter(c => c.userId === req.user.id || c.lawyerId === req.user.id);
  res.json(userCases);
});

// Create appointment (protected)
app.post('/api/appointments', authMiddleware, async (req, res) => {
  const { title, datetime, location, lawyerId } = req.body;
  if (!title || !datetime) return res.status(400).json({ error: 'Missing fields' });

  await db.read();
  const appt = { id: nanoid(), userId: req.user.id, title, datetime, location, lawyerId: lawyerId || null, createdAt: new Date().toISOString() };
  db.data.appointments.push(appt);
  await db.write();
  res.json(appt);
});

// Get appointments (protected)
app.get('/api/appointments', authMiddleware, async (req, res) => {
  await db.read();
  const appts = (db.data.appointments || []).filter(a => a.userId === req.user.id || a.lawyerId === req.user.id);
  res.json(appts);
});

// Basic chat endpoint - uses OpenAI if API key present, otherwise canned
app.post('/api/chat', authMiddleware, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Missing message' });

  if (OPENAI_KEY) {
    try {
      // Basic text completion using OpenAI's Chat Completions (gpt-3.5/4 style) - adapt as needed
      const openaiRes = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${OPENAI_KEY}`
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini', // change if needed; user environment may choose different model
          messages: [{ role: 'system', content: 'You are a helpful legal assistant. Provide high-level, non-lawyerly guidance. Do not give legal advice.' },
                     { role: 'user', content: message }],
          max_tokens: 500
        })
      });
      const data = await openaiRes.json();
      const reply = (data?.choices && data.choices[0]?.message?.content) || 'Sorry — no reply from OpenAI.';
      return res.json({ reply, meta: data });
    } catch (err) {
      console.error('OpenAI error', err);
      return res.status(500).json({ error: 'OpenAI request failed' });
    }
  } else {
    // fallback canned simple response
    const reply = `Thanks for your message: "${message}". Our AI assistant is not configured with an API key. Provide OPENAI_API_KEY to enable richer replies. Meanwhile: you can upload documents, choose a lawyer, or ask for steps to file a complaint.`;
    return res.json({ reply });
  }
});

// Forgot password (simple stub)
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  // in production you'd send an email. Here we simply respond success if user exists.
  await db.read();
  const user = db.data.users.find(u => u.email === email.toLowerCase());
  if (!user) return res.json({ ok: true, message: 'If an account exists you will receive instructions.' });
  // simulate token
  const resetToken = nanoid();
  // store token temporarily on user (not secure, for demo only)
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 1000 * 60 * 60; // 1 hour
  await db.write();
  // in prod: send email with resetToken link
  console.log(`Password reset token for ${email}: ${resetToken}`);
  res.json({ ok: true, message: 'If an account exists you will receive instructions.' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
