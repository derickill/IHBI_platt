require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const path    = require('path');

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

// ── Génération de mot de passe sécurisé ────────────────────────────────────
function generatePassword() {
  const upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower   = 'abcdefghjkmnpqrstuvwxyz';
  const digits  = '23456789';
  const special = '@#!$%';
  const all     = upper + lower + digits + special;
  const bytes   = crypto.randomBytes(12);
  let pwd = '';
  // Au moins un de chaque catégorie
  pwd += upper[bytes[0]  % upper.length];
  pwd += lower[bytes[1]  % lower.length];
  pwd += digits[bytes[2] % digits.length];
  pwd += special[bytes[3] % special.length];
  for (let i = 4; i < 12; i++) pwd += all[bytes[i] % all.length];
  // Mélange (Fisher-Yates)
  const arr = pwd.split('');
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr.join('');
}

// ── Extraction prénom / nom depuis l'email ──────────────────────────────────
function nameFromEmail(email) {
  const local = email.split('@')[0].replace(/[_\-]/g, '.');
  const parts = local.split('.').filter(Boolean);
  const cap   = s => s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : '';
  if (parts.length >= 2) return { prenom: cap(parts[0]), nom: parts.slice(1).map(cap).join(' ') };
  return { prenom: cap(parts[0] || 'Étudiant'), nom: 'IHBI' };
}

// ── Brevo API — envoi d'emails transactionnels via HTTPS ───────────────────
// Doc : https://developers.brevo.com/reference/sendtransacemail
// Prérequis : BREVO_API_KEY + BREVO_FROM (email expéditeur vérifié dans Brevo)
const APP_URL = process.env.APP_URL || '';

async function sendWelcomeEmail(email, prenom, nom, password, classe_id) {
  if (!process.env.BREVO_API_KEY || !process.env.BREVO_FROM) {
    console.log('BREVO_API_KEY ou BREVO_FROM non configuré — email non envoyé');
    return false;
  }

  const htmlContent = `
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;color:#1a1a1a">
      <div style="background:#250D42;padding:24px 32px">
        <h1 style="color:white;font-size:20px;margin:0">IHBI — Plateforme étudiante</h1>
      </div>
      <div style="padding:28px 32px;background:#fff;border:1px solid #e5e7eb">
        <h2 style="font-size:18px;color:#250D42;margin-top:0">Bienvenue, ${prenom} !</h2>
        <p style="color:#555;line-height:1.6">Votre compte étudiant a été créé pour la classe <strong>${classe_id}</strong>. Voici vos identifiants de connexion :</p>
        <div style="background:#f8f9fa;border-left:4px solid #250D42;padding:16px 20px;margin:20px 0;border-radius:0 4px 4px 0">
          <p style="margin:0 0 8px;font-size:14px"><strong>Email :</strong> ${email}</p>
          <p style="margin:0;font-size:14px"><strong>Mot de passe :</strong> <code style="background:#e8e8e8;padding:3px 8px;border-radius:3px;font-size:14px;letter-spacing:.5px">${password}</code></p>
        </div>
        ${APP_URL ? `<a href="${APP_URL}" style="display:inline-block;background:#250D42;color:white;padding:12px 24px;text-decoration:none;font-weight:600;border-radius:3px;margin-bottom:20px">Accéder à la plateforme →</a>` : ''}
        <p style="font-size:12px;color:#999;margin-bottom:0">Pour votre sécurité, nous vous recommandons de changer votre mot de passe après votre première connexion.</p>
      </div>
      <div style="padding:16px 32px;background:#f8f9fa;font-size:11px;color:#999;text-align:center">
        International High Business Institute — IHBI
      </div>
    </div>
  `;

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method:  'POST',
    headers: {
      'api-key':      process.env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      'accept':       'application/json',
    },
    body: JSON.stringify({
      sender:      { name: 'IHBI Platform', email: process.env.BREVO_FROM },
      to:          [{ email, name: `${prenom} ${nom}` }],
      subject:     'Vos identifiants de connexion — IHBI',
      htmlContent,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Brevo API error: ${res.status} — ${err}`);
  }
  return true;
}

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

// ── POST /api/admin/create-students ─────────────────────────────────────────
// Crée des comptes étudiants en masse, génère les mots de passe, envoie les emails
app.post('/api/admin/create-students', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès réservé à l\'administrateur' });

  const { emails, classe_id } = req.body;
  if (!Array.isArray(emails) || !emails.length || !classe_id) {
    return res.status(400).json({ error: 'emails (tableau) et classe_id sont requis' });
  }

  const results = [];
  const errors  = [];

  for (const rawEmail of emails) {
    const email = rawEmail.trim().toLowerCase();
    if (!email.includes('@')) { errors.push({ email, error: 'Adresse invalide' }); continue; }
    try {
      const password = generatePassword();
      const hash     = sha256(password);
      const { prenom, nom } = nameFromEmail(email);

      const { rowCount } = await pool.query(
        `INSERT INTO users (role, nom, prenom, email, pwd_hash, classe_id, status, is_delegue)
         VALUES ('student', $1, $2, $3, $4, $5, 'active', false)
         ON CONFLICT (email) DO NOTHING`,
        [nom, prenom, email, hash, classe_id]
      );

      if (rowCount === 0) { errors.push({ email, error: 'Email déjà utilisé' }); continue; }

      let email_sent = false;
      try { email_sent = await sendWelcomeEmail(email, prenom, nom, password, classe_id); }
      catch (e) { console.error('Email error for', email, ':', e.message); }

      results.push({ email, prenom, nom, classe_id, password, email_sent });
    } catch (err) {
      console.error('Create student error:', err.message);
      errors.push({ email, error: err.message });
    }
  }

  res.json({ results, errors });
});

// ── DELETE /api/admin/users/:id — suppression d'un compte ──────────────────
// On supprime par email (fiable) ET par id (fallback) pour éviter les désynchs
app.delete('/api/admin/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  const email = req.body?.email;
  try {
    let deleted = 0;
    // Suppression par email (source de vérité)
    if (email) {
      const r = await pool.query('DELETE FROM users WHERE LOWER(email) = LOWER($1) AND id != $2', [email, req.user.id]);
      deleted = r.rowCount;
    }
    // Fallback par id si email non fourni ou non trouvé
    if (!deleted) {
      const id = parseInt(req.params.id);
      if (id) await pool.query('DELETE FROM users WHERE id = $1 AND id != $2', [id, req.user.id]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete user error:', err.message);
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
