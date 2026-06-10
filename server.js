require('dotenv').config();
const express  = require('express');
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');
const path     = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname)));

// ── Base de données PostgreSQL ──────────────────────────────────────────────
// En prod : DATABASE_URL fourni automatiquement par Railway
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'ihbi-dev-secret-changez-en-prod';
const JWT_EXPIRES = '7d';

// ── Utilitaires ─────────────────────────────────────────────────────────────
const sha256 = str => crypto.createHash('sha256').update(str).digest('hex');

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expirée, veuillez vous reconnecter' });
  }
}

// ── POST /api/auth/login ────────────────────────────────────────────────────
// Vérifie email + mot de passe, retourne JWT + données de la session
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Champs manquants' });

    const hash = sha256(password);
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1) AND pwd_hash = $2',
      [email, hash]
    );

    if (!rows.length) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const user = rows[0];
    delete user.pwd_hash; // ne jamais renvoyer le hash

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    // Charger le snapshot de données applicatives
    const snap = await pool.query("SELECT value FROM app_data WHERE key = 'main'");
    const data = snap.rows.length ? snap.rows[0].value : {};

    res.json({ token, user, data });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/data — charger les données ────────────────────────────────────
app.get('/api/data', authMiddleware, async (req, res) => {
  try {
    const snap = await pool.query("SELECT value FROM app_data WHERE key = 'main'");
    res.json(snap.rows.length ? snap.rows[0].value : {});
  } catch (err) {
    console.error('Load data error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── POST /api/data — sauvegarder les données ────────────────────────────────
app.post('/api/data', authMiddleware, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO app_data (key, value, updated_at)
       VALUES ('main', $1, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()`,
      [JSON.stringify(req.body)]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('Save data error:', err.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── GET /api/health — vérification Railway ──────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', env: process.env.NODE_ENV }));

// ── Toutes les autres routes → index.html (SPA) ─────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Démarrage ────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Serveur IHBI démarré sur http://localhost:${PORT}`);
});
